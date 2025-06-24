using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using Renci.SshNet;

// Note: Change this namespace to match your project's name
namespace PwServerInstallerWpf
{
    public partial class MainWindow : Window
    {
        private bool _useRoot = false;
        private string _rootPassword = "";
        private bool _useSudo = false;
        private string _privateKeyFilePath;

        public MainWindow()
        {
            InitializeComponent();
            // Populate the version selection dropdown
            cmbVersion.Items.Add("1.5.1");
            cmbVersion.Items.Add("1.5.3");
            cmbVersion.Items.Add("1.5.5");
            cmbVersion.SelectedIndex = 0; // Default to the first item
        }

        private void btnBrowseKey_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Title = "Select Private Key File",
                Filter = "All files (*.*)|*.*"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                _privateKeyFilePath = openFileDialog.FileName;
                // FIX: This line is now enabled to update the UI.
                txtKeyPath.Text = _privateKeyFilePath;
            }
        }

        private void chkUseSshKey_Checked(object sender, RoutedEventArgs e)
        {
            // This event handler is for UI logic, which is handled by binding in the XAML.
            // No additional code is needed here if visibility is bound to the checkbox state.
        }


        private async void btnInstall_Click(object sender, RoutedEventArgs e)
        {
            // FIX: Checkbox state is now correctly read.
            bool useSshKey = chkUseSshKey.IsChecked == true;

            if (string.IsNullOrWhiteSpace(txtHost.Text) ||
                string.IsNullOrWhiteSpace(txtUsername.Text) ||
                // Keep the main password box for sudo, but don't require it for the connection if using a key
                (useSshKey && string.IsNullOrWhiteSpace(_privateKeyFilePath)))
            {
                MessageBox.Show("Please fill in all required SSH connection details.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }


            _useRoot = chkRunAsRoot.IsChecked == true;
            if (_useRoot && string.IsNullOrWhiteSpace(txtRootPassword.Password))
            {
                MessageBox.Show("Please provide the root password when 'Run as root' is checked.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            _rootPassword = _useRoot ? txtRootPassword.Password : "";


            btnInstall.IsEnabled = false;
            txtLog.Clear();

            string host = txtHost.Text;
            string username = txtUsername.Text;
            string userPassword = txtPassword.Password; // This is now for SUDO
            string version = cmbVersion.SelectedItem.ToString();
            string dbPassword = string.IsNullOrWhiteSpace(txtDbPassword.Text)
                ? Path.GetRandomFileName().Replace(".", "").Substring(0, 10)
                : txtDbPassword.Text;

            try
            {
                Log("--- Starting Perfect World Server Installation ---");
                Log($"Selected Version: {version}");
                Log($"Database 'admin' password will be: {dbPassword}");

                SaveCredentialsLocally("Database Credentials", $"Username: admin\nPassword: {dbPassword}");

                await Task.Run(() =>
                {
                    AuthenticationMethod authMethod;
                    if (useSshKey)
                    {
                        Log("Attempting authentication using SSH key.");
                        // FIX: Key passphrase is now correctly read from the password box.
                        string keyPassword = txtKeyPassword.Password;
                        var keyFile = string.IsNullOrWhiteSpace(keyPassword)
                            ? new PrivateKeyFile(_privateKeyFilePath)
                            : new PrivateKeyFile(_privateKeyFilePath, keyPassword);
                        authMethod = new PrivateKeyAuthenticationMethod(username, keyFile);
                    }
                    else
                    {
                        Log("Attempting authentication using password.");
                        authMethod = new PasswordAuthenticationMethod(username, userPassword);
                    }

                    var connectionInfo = new ConnectionInfo(host, username, authMethod);
                    using (var client = new SshClient(connectionInfo))
                    {
                        Log($"Connecting to {host}...");
                        client.Connect();
                        Log("SSH Connection Successful.");

                        RunFullInstallation(client, userPassword, version, dbPassword);

                        client.Disconnect();
                    }
                });


                Log("--- Installation Process Finished Successfully! ---");
                MessageBox.Show("Installation complete! Check logs for details.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Log($"--- A CRITICAL ERROR OCCURRED ---");
                Log($"ERROR: {ex.Message}");
                MessageBox.Show($"An error occurred during installation:\n\n{ex.Message}", "Installation Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                btnInstall.IsEnabled = true;
            }
        }

        #region --- Core Logic and Installation Steps ---

        private void RunFullInstallation(SshClient client, string userPassword, string version, string dbPassword)
        {
            if (_useRoot)
            {
                Log("'Run as root' selected. Bypassing sudo check and using su.");
                _useSudo = false;
            }
            else
            {
                Log("Checking for sudo availability...");
                try
                {
                    var testCmd = client.CreateCommand("sudo -v");
                    testCmd.Execute();
                    var error = testCmd.Error;
                    if (!string.IsNullOrEmpty(error) && error.Contains("sudo: command not found"))
                    {
                        _useSudo = false;
                        Log("Sudo command not found. Assuming user is root. Commands will be run directly.");
                    }
                    else
                    {
                        _useSudo = true;
                        Log("Sudo is available.");
                    }
                }
                catch (Exception)
                {
                    _useSudo = false;
                    Log("Sudo check failed (command not found or user lacks privileges). Assuming non-sudo session.");
                }
            }

            PrepareBaseSystemAndPrereqs(client, userPassword);
            ConfigureSoftwareRepositories(client, userPassword);

            Log("Updating package lists with new repositories...");
            ExecuteCommand(client, userPassword, "apt update -y");

            InstallAllSoftware(client, userPassword);

            DownloadAndExtractServerFiles(client, userPassword, version);
            if (version == "1.5.5")
            {
                DownloadAndInstallLibraries155(client, userPassword);
            }

            DownloadAndExtractWebFiles(client, userPassword);
            DownloadAndConfigurePwAdmin(client, userPassword, dbPassword);
            ConfigureMariaDb(client, userPassword, dbPassword);
            ConfigureHostsFile(client, userPassword);
            ConfigureApplication(client, userPassword, version, dbPassword);
            DownloadAndImportDatabase(client, userPassword, version, dbPassword);
            FinalizeSetup(client, userPassword, version);
        }

        private void PrepareBaseSystemAndPrereqs(SshClient client, string userPassword)
        {
            LogSection("System Preparation");
            Log("Installing core prerequisites (curl, gnupg, etc)...");
            ExecuteCommand(client, userPassword, "apt-get install -y --allow-unauthenticated wget tar software-properties-common curl gnupg lsb-release apt-transport-https ca-certificates unzip");

            Log("Adding i386 architecture...");
            ExecuteCommand(client, userPassword, "dpkg --add-architecture i386");
        }

        private void ConfigureSoftwareRepositories(SshClient client, string userPassword)
        {
            LogSection("Configuring Software Repositories");
            var osRelease = ExecuteCommand(client, userPassword, "cat /etc/os-release");
            if (osRelease.Contains("ID=debian"))
            {
                Log("Debian detected. Adding Sury PHP repository...");
                ExecuteCommand(client, userPassword, "curl -sSL https://packages.sury.org/php/apt.gpg | gpg --dearmor -o /usr/share/keyrings/sury-php-archive-keyring.gpg");
                ExecuteCommand(client, userPassword, "echo \"deb [signed-by=/usr/share/keyrings/sury-php-archive-keyring.gpg] https://packages.sury.org/php/ $(lsb_release -sc) main\" > /etc/apt/sources.list.d/sury-php.list");
            }
            else
            {
                Log("Ubuntu detected. Adding Ondrej PHP PPA...");
                ExecuteCommand(client, userPassword, "add-apt-repository ppa:ondrej/php -y");
            }
        }

        private void InstallAllSoftware(SshClient client, string userPassword)
        {
            LogSection("Installing All Software");
            Log("Installing PHP, Java, Web Server, Database, and libraries...");

            ExecuteCommand(client, userPassword, "apt install -y php8.2 php8.2-cli php8.2-fpm php8.2-curl php8.2-mysql php8.2-gd php8.2-opcache php8.2-zip php8.2-intl php8.2-bcmath php8.2-mbstring php8.2-xml libstdc++6:i386 libxml2:i386");

            var osRelease = ExecuteCommand(client, userPassword, "cat /etc/os-release");
            if (osRelease.Contains("debian"))
            {
                ExecuteCommand(client, userPassword, "apt install -y default-jdk default-jre");
            }
            else
            {
                ExecuteCommand(client, userPassword, "apt-get install -y openjdk-11-jdk openjdk-11-jre");
            }

            ExecuteCommand(client, userPassword, "apt install -y apache2 mariadb-server");
            ExecuteCommand(client, userPassword, "systemctl enable apache2 && systemctl start apache2");
            ExecuteCommand(client, userPassword, "systemctl enable mariadb && systemctl start mariadb");
        }

        private void DownloadAndExtractServerFiles(SshClient client, string userPassword, string version)
        {
            LogSection("Downloading Server Files");
            string serverFileUrl = "", serverFileName = "";
            switch (version)
            {
                case "1.5.1": serverFileUrl = "http://havenpwi.net/install2/Installer/151/1PWServerFiles1.5.1v101.tar.gz"; serverFileName = "1PWServerFiles1.5.1v101.tar.gz"; break;
                case "1.5.3": serverFileUrl = "http://havenpwi.net/install2/Installer/153/PW_153.tar.gz"; serverFileName = "PW_153.tar.gz"; break;
                case "1.5.5": serverFileUrl = "http://havenpwi.net/install2/Installer/155/155V2.tar.gz"; serverFileName = "155V2.tar.gz"; break;
            }
            Log($"Downloading {serverFileName}...");
            ExecuteCommand(client, userPassword, $"wget -O /{serverFileName} {serverFileUrl}");
            Log("Extracting server files...");
            ExecuteCommand(client, userPassword, $"tar kxvzf /{serverFileName} -C /", true);
            Log("Cleaning up downloaded archive...");
            ExecuteCommand(client, userPassword, $"rm /{serverFileName}");
        }

        private void DownloadAndInstallLibraries155(SshClient client, string userPassword)
        {
            LogSection("Installing 1.5.5 Specific Libraries");
            Log("Downloading lib.zip...");
            ExecuteCommand(client, userPassword, "wget -O /tmp/lib.zip http://havenpwi.net/install2/Installer/155/lib.zip");

            Log("Extracting libraries to /usr/lib...");
            ExecuteCommand(client, userPassword, "unzip -o -j /tmp/lib.zip -d /usr/lib");

            Log("Cleaning up lib.zip...");
            ExecuteCommand(client, userPassword, "rm /tmp/lib.zip");
        }

        private void DownloadAndExtractWebFiles(SshClient client, string userPassword)
        {
            LogSection("Downloading Web Registration Files");
            ExecuteCommand(client, userPassword, "wget -O /tmp/reg.zip http://havenpwi.net/install2/Installer/155/PW-Registration-Script-with-Captcha-main.zip");
            Log("Extracting web files to /var/www/html...");
            ExecuteCommand(client, userPassword, "unzip -o /tmp/reg.zip -d /var/www/html");
            Log("Moving extracted files to web root...");
            ExecuteCommand(client, userPassword, "mv /var/www/html/PW-Registration-Script-with-Captcha-main*/* /var/www/html/", true);
            Log("Cleaning up...");
            ExecuteCommand(client, userPassword, "rm -rf /var/www/html/PW-Registration-Script-with-Captcha-main*", true);
            ExecuteCommand(client, userPassword, "rm /tmp/reg.zip");
        }

        private void DownloadAndConfigurePwAdmin(SshClient client, string userPassword, string dbPassword)
        {
            LogSection("Downloading and Configuring PWAdmin");
            ExecuteCommand(client, userPassword, "mkdir -p /home/pwadmin");
            ExecuteCommand(client, userPassword, "wget -O /tmp/pwadmin.zip https://havenpwi.net/installs/pwadmin/pwadminfinalbeta.zip");
            ExecuteCommand(client, userPassword, "unzip -o /tmp/pwadmin.zip -d /home");
            Log("Configuring PWAdmin...");
            string configFile = "/home/pwadmin/webapps/pwadmin/WEB-INF/.pwadminconf.jsp";
            ExecuteCommand(client, userPassword, $"sed -i 's|String db_user.*|String db_user = \"admin\";|' {configFile}");
            ExecuteCommand(client, userPassword, $"sed -i 's|String db_password.*|String db_password = \"{dbPassword}\";|' {configFile}");
            ExecuteCommand(client, userPassword, "rm /tmp/pwadmin.zip");
        }

        private void ConfigureMariaDb(SshClient client, string userPassword, string dbPassword)
        {
            LogSection("Configuring MariaDB");
            Log("Creating 'admin' user and granting privileges...");
            string sqlScriptContent = $@"DROP USER IF EXISTS 'admin'@'localhost';
DROP USER IF EXISTS 'admin'@'%';
CREATE USER 'admin'@'localhost' IDENTIFIED BY '{dbPassword}';
CREATE USER 'admin'@'%' IDENTIFIED BY '{dbPassword}';
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;";

            string linuxSqlScriptContent = sqlScriptContent.Replace("\r\n", "\n");

            string remoteScriptPath = "/tmp/mariadb_setup.sql";
            string catCommand = $"cat << 'EOF' > {remoteScriptPath}\n{linuxSqlScriptContent}\nEOF";
            ExecuteCommand(client, userPassword, catCommand);
            Log($"Created MariaDB setup script at {remoteScriptPath}");

            ExecuteCommand(client, userPassword, $"mysql -u root < {remoteScriptPath}");

            ExecuteCommand(client, userPassword, $"rm {remoteScriptPath}");

            Log("Allowing remote connections to MariaDB...");
            string mariadbConfig = "/etc/mysql/mariadb.conf.d/50-server.cnf";
            ExecuteCommand(client, userPassword, $"sed -i 's/bind-address.*/bind-address = 0.0.0.0/' {mariadbConfig}", true);
            Log("Restarting MariaDB service...");
            ExecuteCommand(client, userPassword, "systemctl restart mariadb");
        }

        private void ConfigureHostsFile(SshClient client, string userPassword)
        {
            LogSection("Configuring /etc/hosts");
            string hostsEntries = @"
127.0.0.1 manager aumanager auth audb link1 link2 game1 game2 game3 game4 delivery database backup gmserver.localdomain gmserver";
            ExecuteCommand(client, userPassword, $"echo '{hostsEntries}' >> /etc/hosts");
        }

        private void ConfigureApplication(SshClient client, string userPassword, string version, string dbPassword)
        {
            LogSection("Configuring Application Files");
            string tableXmlPath = (version == "1.5.1") ? "/etc/table.xml" : "/home/authd/table.xml";
            Log($"Configuring {tableXmlPath}...");
            ExecuteCommand(client, userPassword, $"sed -i 's/username=\"[^\"]*\"/username=\"admin\"/g' {tableXmlPath}");
            ExecuteCommand(client, userPassword, $"sed -i 's/password=\"[^\"]*\"/password=\"{dbPassword}\"/g' {tableXmlPath}");
            Log("Configuring web registration script (config.php)...");
            string configPhpPath = "/var/www/html/config.php";
            ExecuteCommand(client, userPassword, $"sed -i \"s/'user' => '[^']*'/'user' => 'admin'/g\" {configPhpPath}", true);
            ExecuteCommand(client, userPassword, $"sed -i \"s/'pass' => '[^']*'/'pass' => '{dbPassword}'/g\" {configPhpPath}", true);
            ExecuteCommand(client, userPassword, $"sed -i \"s/'name' => '[^']*'/'name' => 'pw'/g\" {configPhpPath}", true);
        }

        private void DownloadAndImportDatabase(SshClient client, string userPassword, string version, string dbPassword)
        {
            LogSection("Importing Database");
            ExecuteCommand(client, userPassword, $"mysql -u admin -p'{dbPassword}' -e 'CREATE DATABASE IF NOT EXISTS pw;'");
            string sqlUrl = "", sqlFile = "";
            switch (version)
            {
                case "1.5.3":
                    sqlUrl = "http://havenpwi.net/install2/Installer/153/db.sql";
                    sqlFile = "db.sql";
                    break;
                case "1.5.1": // Fallthrough to use 1.5.5's database
                case "1.5.5":
                    sqlUrl = "http://havenpwi.net/install2/Installer/155/pwa.sql";
                    sqlFile = "pwa.sql";
                    break;
            }
            string localSqlPath = $"/tmp/{sqlFile}";
            Log($"Downloading database file {sqlFile} for version {version}...");
            ExecuteCommand(client, userPassword, $"wget -O {localSqlPath} {sqlUrl}");

            // Check file type
            var fileType = ExecuteCommand(client, userPassword, $"file {localSqlPath}");
            Log($"Downloaded file type: {fileType}");
            if (fileType.Contains("HTML document"))
            {
                Log("ERROR: Downloaded file is an HTML document, not a SQL file. The download URL may be broken.");
                ExecuteCommand(client, userPassword, $"rm {localSqlPath}");
                throw new Exception("Failed to download the database file. Received an HTML page instead of SQL.");
            }

            Log("Importing database (this may take a while)...");
            ExecuteCommand(client, userPassword, $"mysql -u admin -p'{dbPassword}' pw -e \"source {localSqlPath}\"", false, 600);
            ExecuteCommand(client, userPassword, $"rm {localSqlPath}");
        }

        private void FinalizeSetup(SshClient client, string userPassword, string version)
        {
            LogSection("Finalizing Setup");
            Log("Enabling PHP-FPM for Apache...");
            ExecuteCommand(client, userPassword, "a2enmod proxy_fcgi setenvif && a2enconf php8.2-fpm && systemctl restart apache2");

            Log("Downloading and configuring start scripts...");
            ExecuteCommand(client, userPassword, "wget -O /home/chmod.sh https://havenpwi.net/install2/Installer/scripts153/chmod.sh");
            ExecuteCommand(client, userPassword, "wget -O /home/server https://havenpwi.net/install2/Installer/scripts153/server");
            ExecuteCommand(client, userPassword, "chmod 755 /home/chmod.sh");
            ExecuteCommand(client, userPassword, "chmod 755 /home/server");

            if (version == "1.5.1")
            {
                Log("Downloading maps file for version 1.5.1...");
                ExecuteCommand(client, userPassword, "wget -O /home/maps https://havenpwi.net/install2/Installer/scriptso/maps");
                ExecuteCommand(client, userPassword, "chmod 755 /home/maps");
            }

            Log("Setting final file permissions...");
            Log("Determining web server user...");
            string webServerUser = ExecuteCommand(client, userPassword, "ps -eo user,comm --no-headers | grep -E 'apache2|httpd|nginx|www-data' | head -n1 | awk '{print $1}'").Trim();
            if (string.IsNullOrWhiteSpace(webServerUser))
            {
                webServerUser = "www-data";
                Log($"Could not detect running web server user, falling back to default: {webServerUser}");
            }
            else
            {
                Log($"Detected web server user: {webServerUser}");
            }

            ExecuteCommand(client, userPassword, $"chown -R {webServerUser}:{webServerUser} /var/www/html /home/pwadmin");
            ExecuteCommand(client, userPassword, "find /var/www/html -type d -exec chmod 755 {} \\;");
            ExecuteCommand(client, userPassword, "find /var/www/html -type f -exec chmod 644 {} \\;");
            Log("Applying recursive 755 permissions to /home folder...");
            ExecuteCommand(client, userPassword, "chmod -R 755 /home", true);
        }
        #endregion

        #region --- PW-Panel Installation ---

        private async void btnInstallPanel_Click(object sender, RoutedEventArgs e)
        {
            // FIX: Checkbox state is now correctly read.
            bool useSshKey = chkUseSshKey.IsChecked == true;

            if (string.IsNullOrWhiteSpace(txtHost.Text) ||
                string.IsNullOrWhiteSpace(txtUsername.Text) ||
                (useSshKey && string.IsNullOrWhiteSpace(_privateKeyFilePath)))
            {
                MessageBox.Show("Please fill in all required SSH connection details.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            // --- FIX: Added logic to check for root/sudo selection for the panel install ---
            _useRoot = chkRunAsRoot.IsChecked == true;
            if (_useRoot && string.IsNullOrWhiteSpace(txtRootPassword.Password))
            {
                MessageBox.Show("Please provide the root password when 'Run as root' is checked.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            _rootPassword = _useRoot ? txtRootPassword.Password : "";

            btnInstallPanel.IsEnabled = false;
            txtLog.Clear();

            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Title = "Select Database Credentials File",
                Filter = "Text Files (*.txt)|*.txt|All files (*.*)|*.*"
            };

            if (openFileDialog.ShowDialog() != true)
            {
                MessageBox.Show("Panel installation cancelled. You must select a credentials file.", "Cancelled", MessageBoxButton.OK, MessageBoxImage.Warning);
                btnInstallPanel.IsEnabled = true;
                return;
            }

            string filePath = openFileDialog.FileName;
            string dbUser, dbPassword;

            try
            {
                string fileContent = File.ReadAllText(filePath);
                dbUser = new Regex(@"Username:\s*(.+)").Match(fileContent).Groups[1].Value.Trim();
                dbPassword = new Regex(@"Password:\s*(.+)").Match(fileContent).Groups[1].Value.Trim();

                if (string.IsNullOrWhiteSpace(dbUser) || string.IsNullOrWhiteSpace(dbPassword))
                {
                    throw new Exception("File format is incorrect. Could not find Username or Password.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Could not read credentials from the selected file.\n\nError: {ex.Message}\n\nPlease ensure it is the correct file and format.", "File Read Error", MessageBoxButton.OK, MessageBoxImage.Error);
                btnInstallPanel.IsEnabled = true;
                return;
            }

            string host = txtHost.Text;
            string username = txtUsername.Text;
            string userPassword = txtPassword.Password;
            string panelCredentials = null;

            try
            {
                Log("--- Starting PW-Panel Installation ---");
                Log($"Read credentials from '{Path.GetFileName(filePath)}': User='{dbUser}'");

                panelCredentials = await Task.Run<string>(() =>
                {
                    AuthenticationMethod authMethod;
                    if (useSshKey)
                    {
                        Log("Attempting authentication using SSH key.");
                        // FIX: Key passphrase is now correctly read from the password box.
                        string keyPassword = txtKeyPassword.Password;
                        var keyFile = string.IsNullOrWhiteSpace(keyPassword)
                            ? new PrivateKeyFile(_privateKeyFilePath)
                            : new PrivateKeyFile(_privateKeyFilePath, keyPassword);
                        authMethod = new PrivateKeyAuthenticationMethod(username, keyFile);
                    }
                    else
                    {
                        Log("Attempting authentication using password.");
                        authMethod = new PasswordAuthenticationMethod(username, userPassword);
                    }
                    var connectionInfo = new ConnectionInfo(host, username, authMethod);
                    using (var client = new SshClient(connectionInfo))
                    {
                        Log($"Connecting to {host}...");
                        client.Connect();
                        Log("SSH Connection Successful.");

                        string creds = RunPanelInstallation(client, userPassword, dbUser, dbPassword);

                        client.Disconnect();
                        return creds;
                    }
                });

                Log("--- PW-Panel Installation Finished Successfully! ---");
                MessageBox.Show("Panel installation complete! Check logs for details.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                Log($"--- A CRITICAL ERROR OCCURRED during Panel Installation ---");
                Log($"ERROR: {ex.Message}");
                MessageBox.Show($"An error occurred during panel installation:\n\n{ex.Message}", "Installation Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                if (!string.IsNullOrEmpty(panelCredentials))
                {
                    SaveCredentialsLocally("Panel Admin Credentials", panelCredentials);
                }
                btnInstallPanel.IsEnabled = true;
            }
        }

        private string RunPanelInstallation(SshClient client, string userPassword, string dbUser, string dbPassword)
        {
            if (_useRoot)
            {
                Log("'Run as root' selected. Bypassing sudo check and using su.");
                _useSudo = false;
            }
            else
            {
                Log("Checking for sudo availability for Panel installation...");
                try
                {
                    var testCmd = client.CreateCommand("sudo -v");
                    testCmd.Execute();
                    var error = testCmd.Error;
                    if (!string.IsNullOrEmpty(error) && error.Contains("sudo: command not found"))
                    {
                        _useSudo = false;
                    }
                    else
                    {
                        _useSudo = true;
                    }
                }
                catch (Exception)
                {
                    _useSudo = false;
                }
                Log(_useSudo ? "Sudo is available." : "Sudo not found or user lacks privileges. Assuming root session.");
            }

            string osRelease = ExecuteCommand(client, userPassword, "cat /etc/os-release");
            if (osRelease.Contains("ID=fedora") || osRelease.Contains("ID_LIKE=rhel"))
            {
                Log("Detected Fedora/RHEL-based system.");
                return InstallPanelOnFedora(client, userPassword, dbUser, dbPassword);
            }
            else if (osRelease.Contains("ID=debian") || osRelease.Contains("ID_LIKE=debian") || osRelease.Contains("ID=ubuntu"))
            {
                Log("Detected Debian/Ubuntu-based system.");
                return InstallPanelOnDebian(client, userPassword, dbUser, dbPassword);
            }
            else
            {
                throw new Exception("Unsupported OS. Please use a Fedora/RHEL or Debian/Ubuntu based distribution.");
            }
        }

        private string InstallPanelOnDebian(SshClient client, string userPassword, string dbUser, string dbPassword)
        {
            LogSection("Panel Installation on Debian/Ubuntu");

            string destDir = "/var/www/html";
            string finalDir = "panel";
            string panelDir = $"{destDir}/{finalDir}";
            string apacheDefaultSite = "/etc/apache2/sites-available/000-default.conf";
            string apacheConf = "/etc/apache2/apache2.conf";
            string apacheConfUrl = "http://havenpwi.net/installs/New%20Installer/panel/apache2.conf";

            ExecuteCommand(client, userPassword, "apt-get update -y");
            ExecuteCommand(client, userPassword, "apt-get install -y unzip");
            DownloadAndExtractPanel(client, userPassword, destDir, finalDir);
            ConfigurePanelEnvFile(client, userPassword, panelDir, dbUser, dbPassword);
            InstallComposerOnDebian(client, userPassword);
            SetPanelPermissions(client, userPassword, panelDir);
            DownloadAndImportPanelDb(client, userPassword, panelDir, dbUser, dbPassword);
            ConfigurePanelEncryption(client, userPassword, panelDir);
            RunLaravelSetup(client, userPassword, panelDir);
            string panelCredentials = CreatePanelAdminUser(client, userPassword, panelDir);

            Log("Modifying Apache configuration...");
            ExecuteCommand(client, userPassword, $"wget -q -O {apacheConf} {apacheConfUrl}");
            ExecuteCommand(client, userPassword, $"sed -i \"s|DocumentRoot /var/www/html|DocumentRoot /var/www/html/panel/public|\" {apacheDefaultSite}", true);
            Log("Enabling mod_rewrite...");
            ExecuteCommand(client, userPassword, "a2enmod rewrite");
            Log("Restarting apache2 service...");
            ExecuteCommand(client, userPassword, "systemctl restart apache2");
            ExecuteCommand(client, userPassword, "rm /tmp/dbo.sql");

            return panelCredentials;
        }

        private string InstallPanelOnFedora(SshClient client, string userPassword, string dbUser, string dbPassword)
        {
            LogSection("Panel Installation on Fedora/RHEL");

            string destDir = "/var/www/html";
            string finalDir = "panel";
            string panelDir = $"{destDir}/{finalDir}";
            string apacheConf = "/etc/httpd/conf/httpd.conf";
            string apacheConfUrl = "http://havenpwi.net/installs/New%20Installer/panel/httpd.conf";

            ExecuteCommand(client, userPassword, "dnf check-update -y");
            ExecuteCommand(client, userPassword, "dnf install -y unzip composer");
            DownloadAndExtractPanel(client, userPassword, destDir, finalDir);
            ConfigurePanelEnvFile(client, userPassword, panelDir, dbUser, dbPassword);
            SetPanelPermissions(client, userPassword, panelDir);
            DownloadAndImportPanelDb(client, userPassword, panelDir, dbUser, dbPassword);
            ConfigurePanelEncryption(client, userPassword, panelDir);
            RunLaravelSetup(client, userPassword, panelDir);
            string panelCredentials = CreatePanelAdminUser(client, userPassword, panelDir);

            Log("Modifying Apache configuration...");
            ExecuteCommand(client, userPassword, $"wget -q -O {apacheConf} {apacheConfUrl}");
            Log("Restarting httpd service...");
            ExecuteCommand(client, userPassword, "systemctl restart httpd");
            ExecuteCommand(client, userPassword, "rm /tmp/dbo.sql");

            return panelCredentials;
        }

        private void DownloadAndExtractPanel(SshClient client, string userPassword, string destDir, string finalDir)
        {
            LogSection("Downloading and Extracting Panel Files");
            string sourceUrl = "https://github.com/hrace009/PW-Panel/archive/refs/heads/master.zip";
            string tempZip = "/tmp/panel.zip";
            string extractedDirName = "PW-Panel-master";

            ExecuteCommand(client, userPassword, $"wget -q '{sourceUrl}' -O {tempZip}");
            ExecuteCommand(client, userPassword, $"mkdir -p {destDir}");
            ExecuteCommand(client, userPassword, $"unzip -q -o {tempZip} -d {destDir}");
            ExecuteCommand(client, userPassword, $"mv {destDir}/{extractedDirName} {destDir}/{finalDir}");
            ExecuteCommand(client, userPassword, $"rm {tempZip}");
        }

        private void ConfigurePanelEnvFile(SshClient client, string userPassword, string panelDir, string dbUser, string dbPass)
        {
            LogSection("Configuring .env file");
            string envExampleFile = $"{panelDir}/.env.example";
            string envFile = $"{panelDir}/.env";

            ExecuteCommand(client, userPassword, $"sed -i 's/DB_DATABASE=laravel/DB_DATABASE=pw/' {envExampleFile}");
            ExecuteCommand(client, userPassword, $"sed -i 's/DB_USERNAME=root/DB_USERNAME={dbUser}/' {envExampleFile}");
            ExecuteCommand(client, userPassword, $"sed -i 's/DB_PASSWORD=/DB_PASSWORD={dbPass}/' {envExampleFile}");
            ExecuteCommand(client, userPassword, $"mv {envExampleFile} {envFile}");
        }

        private void ConfigurePanelEncryption(SshClient client, string userPassword, string panelDir)
        {
            LogSection("Configuring Panel Encryption");
            string configFile = $"{panelDir}/config/pw-config.php";
            string checkFileCmd = $"test -f {configFile} && echo 'exists'";
            string fileExists = ExecuteCommand(client, userPassword, checkFileCmd, true);

            if (fileExists.Trim() == "exists")
            {
                Log($"Updating encryption type in {configFile}...");
                string command = $"sed -i \"s/'encryption_type' => 'md5'/'encryption_type' => 'base64'/\" {configFile}";
                ExecuteCommand(client, userPassword, command);
            }
            else
            {
                Log($"Warning: Configuration file {configFile} not found. Skipping encryption type update.");
            }
        }

        private void InstallComposerOnDebian(SshClient client, string userPassword)
        {
            LogSection("Installing Composer on Debian");
            string composerCheck = ExecuteCommand(client, userPassword, "command -v composer", true);
            if (!string.IsNullOrWhiteSpace(composerCheck))
            {
                string composerVersion = ExecuteCommand(client, userPassword, "composer --version", true);
                if (composerVersion.Contains("Composer version 1."))
                {
                    Log("Composer 1 found, uninstalling...");
                    ExecuteCommand(client, userPassword, "apt-get remove --purge composer -y");
                }
                else
                {
                    Log("Composer 2 or newer already installed.");
                    return;
                }
            }

            string installerUrl = "https://getcomposer.org/installer";
            string installerFile = "/tmp/composer-installer.php";
            ExecuteCommand(client, userPassword, $"wget -q '{installerUrl}' -O {installerFile}");
            ExecuteCommand(client, userPassword, $"php {installerFile} --install-dir=/usr/local/bin --filename=composer");
            ExecuteCommand(client, userPassword, $"rm {installerFile}");
        }

        private void SetPanelPermissions(SshClient client, string userPassword, string panelDir)
        {
            LogSection("Setting Panel Permissions");
            ExecuteCommand(client, userPassword, $"cd {panelDir} && chmod -R 777 storage bootstrap app config");
        }

        private void DownloadAndImportPanelDb(SshClient client, string userPassword, string panelDir, string dbUser, string dbPass)
        {
            LogSection("Downloading and Importing Panel Database");
            string sqlFileUrl = "http://havenpwi.net/installs/New%20Installer/panel/dbo.sql";
            string sqlFileLocal = "/tmp/dbo.sql";

            ExecuteCommand(client, userPassword, $"wget -q '{sqlFileUrl}' -O {sqlFileLocal}");
            ExecuteCommand(client, userPassword, $"mysql -u'{dbUser}' -p'{dbPass}' pw < {sqlFileLocal}");
        }

        private void RunLaravelSetup(SshClient client, string userPassword, string panelDir)
        {
            LogSection("Running Laravel Setup");
            string phpPath = "php";
            string composerPath = "composer";

            ExecuteCommand(client, userPassword, $"cd {panelDir} && yes | {composerPath} install --optimize-autoloader --no-dev", false, 600);
            ExecuteCommand(client, userPassword, $"cd {panelDir} && yes | {phpPath} artisan config:cache");
            ExecuteCommand(client, userPassword, $"cd {panelDir} && yes | {composerPath} install", false, 600);
            ExecuteCommand(client, userPassword, $"cd {panelDir} && yes | {phpPath} artisan migrate");
            ExecuteCommand(client, userPassword, $"cd {panelDir} && yes | {phpPath} artisan db:seed --class=ServiceSeeder");
            ExecuteCommand(client, userPassword, $"cd {panelDir} && yes | {phpPath} artisan key:generate");
        }

        private string CreatePanelAdminUser(SshClient client, string userPassword, string panelDir)
        {
            LogSection("Creating Panel Admin User");
            string adminUsername = "admin";
            string adminEmail = "randomperson@gmail.com";
            string adminFullname = "randomdev";

            string command = $"cd {panelDir} && echo -e '{adminUsername}\\n{adminEmail}\\n{adminFullname}\\n' | php artisan pw:createAdmin";
            string adminOutput = ExecuteCommand(client, userPassword, command);

            var match = Regex.Match(adminOutput, @"Password: (.*)");
            if (!match.Success)
            {
                throw new Exception("Failed to extract the admin password from the output.");
            }
            string adminPassword = match.Groups[1].Value.Trim();

            Log($"Admin user created: Username={adminUsername}, Password={adminPassword}");
            string credentialsContent = $"Username: {adminUsername}\nEmail: {adminEmail}\nFull Name: {adminFullname}\nPassword: {adminPassword}\n";
            Log("Panel credentials generated. Will prompt to save locally after installation.");
            return credentialsContent;
        }

        #endregion

        #region --- SSH and Logging Helpers ---

        private void LogSection(string section) => Log($"\n--- {section} ---\n");

        private void Log(string message)
        {
            Dispatcher.Invoke(() => {
                txtLog.AppendText(message + Environment.NewLine);
                txtLog.ScrollToEnd();
            });
        }

        private string ExecuteCommand(SshClient client, string userPassword, string command, bool ignoreErrors = false, int timeoutSeconds = 300)
        {
            string commandToExecute;
            string escapedCommand = command.Replace("'", "'\\''");

            if (_useRoot)
            {
                Log($"> su -c \"{command}\"");
                commandToExecute = $"echo '{_rootPassword}' | su - -c '{escapedCommand}'";
            }
            else if (_useSudo && !string.IsNullOrWhiteSpace(userPassword))
            {
                Log($"> sudo {command}");
                commandToExecute = $"echo '{userPassword}' | sudo -S -- bash -c '{escapedCommand}'";
            }
            else
            {
                Log($"> {command}");
                commandToExecute = command;
            }

            var cmd = client.CreateCommand(commandToExecute);
            cmd.CommandTimeout = TimeSpan.FromSeconds(timeoutSeconds);
            var result = cmd.Execute();
            var stderr = new StreamReader(cmd.ExtendedOutputStream).ReadToEnd();
            if (!string.IsNullOrWhiteSpace(stderr)) Log($"STDERR: {stderr}");
            if (cmd.ExitStatus != 0 && !ignoreErrors) throw new Exception($"Command failed with exit code {cmd.ExitStatus}.\nError: {stderr}\nCommand: {command}");
            return result;
        }

        private void SaveCredentialsLocally(string title, string content)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog
            {
                Title = $"Save {title}",
                FileName = $"{title.Replace(" ", "_")}.txt",
                Filter = "Text File | *.txt"
            };

            if (saveFileDialog.ShowDialog() == true)
            {
                File.WriteAllText(saveFileDialog.FileName, content);
                Log($"Saved {title} to: {saveFileDialog.FileName}");
            }
        }
        #endregion
    }
}