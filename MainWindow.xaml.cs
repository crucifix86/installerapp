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
        public MainWindow()
        {
            InitializeComponent();
            // Populate the version selection dropdown
            cmbVersion.Items.Add("1.5.1");
            cmbVersion.Items.Add("1.5.3");
            cmbVersion.Items.Add("1.5.5");
            cmbVersion.SelectedIndex = 0; // Default to the first item
        }

        private async void btnInstall_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtHost.Text) ||
                string.IsNullOrWhiteSpace(txtUsername.Text) ||
                string.IsNullOrWhiteSpace(txtPassword.Password))
            {
                MessageBox.Show("Please fill in all SSH connection details.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            btnInstall.IsEnabled = false;
            txtLog.Clear();

            // --- ROBUST THREADING FIX ---
            // Read all values from UI controls into local variables on the UI thread FIRST.
            // The background task will only use these variables, ensuring it never touches a UI element.
            string host = txtHost.Text;
            string username = txtUsername.Text;
            string userPassword = txtPassword.Password;
            string version = cmbVersion.SelectedItem.ToString();
            string dbPassword = string.IsNullOrWhiteSpace(txtDbPassword.Text)
                ? Path.GetRandomFileName().Replace(".", "").Substring(0, 10)
                : txtDbPassword.Text;

            try
            {
                Log("--- Starting Perfect World Server Installation ---");
                Log($"Selected Version: {version}");
                Log($"Database 'admin' password will be: {dbPassword}");

                // Prompt to save DB credentials locally - This runs on the UI thread before the background task starts.
                SaveCredentialsLocally("Database Credentials", $"Username: admin\nPassword: {dbPassword}");

                // The background task now only captures the safe, local variables.
                await Task.Run(() =>
                {
                    var connectionInfo = new ConnectionInfo(host, username, new PasswordAuthenticationMethod(username, userPassword));
                    using (var client = new SshClient(connectionInfo))
                    {
                        Log($"Connecting to {host}...");
                        client.Connect();
                        Log("SSH Connection Successful.");

                        // Execute the installation sequence.
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

        /// <summary>
        /// Main orchestrator for the installation process.
        /// </summary>
        private void RunFullInstallation(SshClient client, string userPassword, string version, string dbPassword)
        {
            // --- Sudo Detection Logic ---
            bool useSudo = true;
            Log("Checking for sudo availability...");
            try
            {
                var testCmd = client.CreateCommand("sudo -v");
                testCmd.Execute();
                var error = testCmd.Error;
                if (!string.IsNullOrEmpty(error) && error.Contains("sudo: command not found"))
                {
                    useSudo = false;
                    Log("Sudo command not found. Assuming root session. Commands will be run directly.");
                }
                else
                {
                    Log("Sudo is available.");
                }
            }
            catch (Exception)
            {
                useSudo = false;
                Log("Sudo command not found. Assuming root session. Commands will be run directly.");
            }


            // --- Phase 1: System Preparation ---
            DetectOSAndInstallBase(client, userPassword, useSudo);
            InstallPhpAndDependencies(client, userPassword, useSudo);
            InstallJava(client, userPassword, useSudo);
            InstallWebServerAndDB(client, userPassword, useSudo);

            // --- Phase 2: Download and Extract Files ---
            DownloadAndExtractServerFiles(client, userPassword, useSudo, version);

            // Version 1.5.5 has a special library installation step
            if (version == "1.5.5")
            {
                DownloadAndInstallLibraries155(client, userPassword, useSudo);
            }

            DownloadAndExtractWebFiles(client, userPassword, useSudo);
            DownloadAndConfigurePwAdmin(client, userPassword, useSudo, dbPassword);

            // --- Phase 3: Configuration ---
            ConfigureMariaDb(client, userPassword, useSudo, dbPassword);
            ConfigureHostsFile(client, userPassword, useSudo);
            ConfigureApplication(client, userPassword, useSudo, version, dbPassword);

            // --- Phase 4: Database Import ---
            DownloadAndImportDatabase(client, userPassword, useSudo, version, dbPassword);

            // --- Phase 5: Finalization ---
            FinalizeSetup(client, userPassword, useSudo, version);
        }

        private void DetectOSAndInstallBase(SshClient client, string userPassword, bool useSudo)
        {
            LogSection("System Preparation");
            Log("Updating package lists...");
            ExecuteCommand(client, userPassword, "apt update -y", useSudo);

            Log("Installing common prerequisites...");
            ExecuteCommand(client, userPassword, "apt install -y wget tar software-properties-common curl gnupg lsb-release apt-transport-https ca-certificates unzip", useSudo);

            Log("Adding i386 architecture...");
            ExecuteCommand(client, userPassword, "dpkg --add-architecture i386", useSudo);
            ExecuteCommand(client, userPassword, "apt update -y", useSudo);

            Log("Installing 32-bit libraries...");
            ExecuteCommand(client, userPassword, "apt install -y libstdc++6:i386 libxml2:i386", useSudo);
        }

        private void InstallPhpAndDependencies(SshClient client, string userPassword, bool useSudo)
        {
            LogSection("PHP Installation");
            var osRelease = ExecuteCommand(client, userPassword, "cat /etc/os-release", useSudo);
            if (osRelease.Contains("ID=debian"))
            {
                Log("Debian detected. Adding Sury PHP repository...");
                ExecuteCommand(client, userPassword, "curl -sSL https://packages.sury.org/php/apt.gpg | gpg --dearmor -o /usr/share/keyrings/sury-php-archive-keyring.gpg", useSudo);
                ExecuteCommand(client, userPassword, "echo \"deb [signed-by=/usr/share/keyrings/sury-php-archive-keyring.gpg] https://packages.sury.org/php/ $(lsb_release -sc) main\" > /etc/apt/sources.list.d/sury-php.list", useSudo);
            }
            else
            {
                Log("Ubuntu detected. Adding Ondrej PHP PPA...");
                ExecuteCommand(client, userPassword, "add-apt-repository ppa:ondrej/php -y", useSudo);
            }
            ExecuteCommand(client, userPassword, "apt update -y", useSudo);
            Log("Installing PHP 8.2 and extensions...");
            ExecuteCommand(client, userPassword, "apt install -y php8.2 php8.2-cli php8.2-fpm php8.2-curl php8.2-mysql php8.2-gd php8.2-opcache php8.2-zip php8.2-intl php8.2-bcmath php8.2-mbstring php8.2-xml", useSudo);
        }

        private void InstallJava(SshClient client, string userPassword, bool useSudo)
        {
            LogSection("Java Installation");
            var osRelease = ExecuteCommand(client, userPassword, "cat /etc/os-release", useSudo);
            if (osRelease.Contains("debian"))
            {
                Log("Installing default JDK/JRE for Debian...");
                ExecuteCommand(client, userPassword, "apt install -y default-jdk default-jre", useSudo);
            }
            else
            {
                Log("Installing OpenJDK 11 for Ubuntu...");
                ExecuteCommand(client, userPassword, "apt-get install -y openjdk-11-jdk openjdk-11-jre", useSudo);
            }
        }

        private void InstallWebServerAndDB(SshClient client, string userPassword, bool useSudo)
        {
            LogSection("Web Server and Database Installation");
            Log("Installing Apache2 web server...");
            ExecuteCommand(client, userPassword, "apt install -y apache2", useSudo);
            ExecuteCommand(client, userPassword, "systemctl enable apache2 && systemctl start apache2", useSudo);
            Log("Installing MariaDB server...");
            ExecuteCommand(client, userPassword, "apt install -y mariadb-server", useSudo);
            ExecuteCommand(client, userPassword, "systemctl enable mariadb && systemctl start mariadb", useSudo);
        }

        private void DownloadAndExtractServerFiles(SshClient client, string userPassword, bool useSudo, string version)
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
            ExecuteCommand(client, userPassword, $"wget -O /{serverFileName} {serverFileUrl}", useSudo);
            Log("Extracting server files...");
            ExecuteCommand(client, userPassword, $"tar kxvzf /{serverFileName} -C /", useSudo);
            Log("Cleaning up downloaded archive...");
            ExecuteCommand(client, userPassword, $"rm /{serverFileName}", useSudo);
        }

        private void DownloadAndInstallLibraries155(SshClient client, string userPassword, bool useSudo)
        {
            LogSection("Installing 1.5.5 Specific Libraries");
            Log("Downloading lib.zip...");
            ExecuteCommand(client, userPassword, "wget -O /tmp/lib.zip http://havenpwi.net/install2/Installer/155/lib.zip", useSudo);

            Log("Extracting libraries to /usr/lib...");
            // The -j flag is crucial here. It junks the paths and extracts files directly to the target directory.
            ExecuteCommand(client, userPassword, "unzip -o -j /tmp/lib.zip -d /usr/lib", useSudo);

            Log("Cleaning up lib.zip...");
            ExecuteCommand(client, userPassword, "rm /tmp/lib.zip", useSudo);
        }

        private void DownloadAndExtractWebFiles(SshClient client, string userPassword, bool useSudo)
        {
            LogSection("Downloading Web Registration Files");
            ExecuteCommand(client, userPassword, "wget -O /tmp/reg.zip http://havenpwi.net/install2/Installer/155/PW-Registration-Script-with-Captcha-main.zip", useSudo);
            Log("Extracting web files to /var/www/html...");
            ExecuteCommand(client, userPassword, "unzip -o /tmp/reg.zip -d /var/www/html", useSudo);
            Log("Moving extracted files to web root...");
            ExecuteCommand(client, userPassword, "mv /var/www/html/PW-Registration-Script-with-Captcha-main*/* /var/www/html/", useSudo, true);
            Log("Cleaning up...");
            ExecuteCommand(client, userPassword, "rm -rf /var/www/html/PW-Registration-Script-with-Captcha-main*", useSudo, true);
            ExecuteCommand(client, userPassword, "rm /tmp/reg.zip", useSudo);
        }

        private void DownloadAndConfigurePwAdmin(SshClient client, string userPassword, bool useSudo, string dbPassword)
        {
            LogSection("Downloading and Configuring PWAdmin");
            ExecuteCommand(client, userPassword, "mkdir -p /home/pwadmin", useSudo);
            ExecuteCommand(client, userPassword, "wget -O /tmp/pwadmin.zip https://havenpwi.net/installs/pwadmin/pwadminfinalbeta.zip", useSudo);
            ExecuteCommand(client, userPassword, "unzip -o /tmp/pwadmin.zip -d /home", useSudo);
            Log("Configuring PWAdmin...");
            string configFile = "/home/pwadmin/webapps/pwadmin/WEB-INF/.pwadminconf.jsp";
            ExecuteCommand(client, userPassword, $"sed -i 's|String db_user.*|String db_user = \"admin\";|' {configFile}", useSudo);
            ExecuteCommand(client, userPassword, $"sed -i 's|String db_password.*|String db_password = \"{dbPassword}\";|' {configFile}", useSudo);
            ExecuteCommand(client, userPassword, "rm /tmp/pwadmin.zip", useSudo);
        }

        private void ConfigureMariaDb(SshClient client, string userPassword, bool useSudo, string dbPassword)
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

            // Replace Windows line endings (\r\n) with Linux line endings (\n)
            string linuxSqlScriptContent = sqlScriptContent.Replace("\r\n", "\n");

            // Use a 'here document' with cat to reliably write the SQL to a file on the server.
            // This avoids all shell escaping issues with echo.
            string remoteScriptPath = "/tmp/mariadb_setup.sql";
            string catCommand = $"cat << 'EOF' > {remoteScriptPath}\n{linuxSqlScriptContent}\nEOF";
            ExecuteCommand(client, userPassword, catCommand, useSudo);
            Log($"Created MariaDB setup script at {remoteScriptPath}");

            // Execute the script using mysql source command.
            ExecuteCommand(client, userPassword, $"mysql -u root < {remoteScriptPath}", useSudo);

            // Clean up the script file.
            ExecuteCommand(client, userPassword, $"rm {remoteScriptPath}", useSudo);

            Log("Allowing remote connections to MariaDB...");
            string mariadbConfig = "/etc/mysql/mariadb.conf.d/50-server.cnf";
            ExecuteCommand(client, userPassword, $"sed -i 's/bind-address.*/bind-address = 0.0.0.0/' {mariadbConfig}", useSudo);
            Log("Restarting MariaDB service...");
            ExecuteCommand(client, userPassword, "systemctl restart mariadb", useSudo);
        }

        private void ConfigureHostsFile(SshClient client, string userPassword, bool useSudo)
        {
            LogSection("Configuring /etc/hosts");
            string hostsEntries = @"
127.0.0.1 manager aumanager auth audb link1 link2 game1 game2 game3 game4 delivery database backup gmserver.localdomain gmserver";
            ExecuteCommand(client, userPassword, $"echo '{hostsEntries}' >> /etc/hosts", useSudo);
        }

        private void ConfigureApplication(SshClient client, string userPassword, bool useSudo, string version, string dbPassword)
        {
            LogSection("Configuring Application Files");
            string tableXmlPath = (version == "1.5.1") ? "/etc/table.xml" : "/home/authd/table.xml";
            Log($"Configuring {tableXmlPath}...");
            // Use non-greedy regex [^"]* to avoid deleting rest of the line.
            ExecuteCommand(client, userPassword, $"sed -i 's/username=\"[^\"]*\"/username=\"admin\"/g' {tableXmlPath}", useSudo);
            ExecuteCommand(client, userPassword, $"sed -i 's/password=\"[^\"]*\"/password=\"{dbPassword}\"/g' {tableXmlPath}", useSudo);
            Log("Configuring web registration script (config.php)...");
            string configPhpPath = "/var/www/html/config.php";
            ExecuteCommand(client, userPassword, $"sed -i \"s/'user' => '[^']*'/'user' => 'admin'/g\" {configPhpPath}", useSudo, true);
            ExecuteCommand(client, userPassword, $"sed -i \"s/'pass' => '[^']*'/'pass' => '{dbPassword}'/g\" {configPhpPath}", useSudo, true);
            ExecuteCommand(client, userPassword, $"sed -i \"s/'name' => '[^']*'/'name' => 'pw'/g\" {configPhpPath}", useSudo, true);
        }

        private void DownloadAndImportDatabase(SshClient client, string userPassword, bool useSudo, string version, string dbPassword)
        {
            LogSection("Importing Database");
            ExecuteCommand(client, userPassword, $"mysql -u admin -p'{dbPassword}' -e 'CREATE DATABASE IF NOT EXISTS pw;'", useSudo);
            string sqlUrl = "", sqlFile = "";
            switch (version)
            {
                case "1.5.1":
                    Log("Skipping DB import for 1.5.1 as pw.sql must be placed manually in /home/SQL/");
                    ExecuteCommand(client, userPassword, "mkdir -p /home/SQL", useSudo);
                    return;
                case "1.5.3": sqlUrl = "http://havenpwi.net/install2/Installer/153/db.sql"; sqlFile = "db.sql"; break;
                case "1.5.5": sqlUrl = "http://havenpwi.net/install2/Installer/155/pwa.sql"; sqlFile = "pwa.sql"; break;
            }
            Log($"Downloading database file {sqlFile}...");
            ExecuteCommand(client, userPassword, $"wget -O /tmp/{sqlFile} {sqlUrl}", useSudo);
            Log("Importing database (this may take a while)...");
            ExecuteCommand(client, userPassword, $"mysql -u admin -p'{dbPassword}' pw < /tmp/{sqlFile}", useSudo, false, 600);
            ExecuteCommand(client, userPassword, $"rm /tmp/{sqlFile}", useSudo);
        }

        private void FinalizeSetup(SshClient client, string userPassword, bool useSudo, string version)
        {
            LogSection("Finalizing Setup");
            Log("Enabling PHP-FPM for Apache...");
            ExecuteCommand(client, userPassword, "a2enmod proxy_fcgi setenvif && a2enconf php8.2-fpm && systemctl restart apache2", useSudo);

            Log("Setting final file permissions...");
            Log("Determining web server user...");
            string webServerUser = ExecuteCommand(client, userPassword, "ps -eo user,comm --no-headers | grep -E 'apache2|httpd|nginx|www-data' | head -n1 | awk '{print $1}'", useSudo).Trim();
            if (string.IsNullOrWhiteSpace(webServerUser))
            {
                webServerUser = "www-data"; // A safe default for Debian/Ubuntu
                Log($"Could not detect running web server user, falling back to default: {webServerUser}");
            }
            else
            {
                Log($"Detected web server user: {webServerUser}");
            }

            ExecuteCommand(client, userPassword, $"chown -R {webServerUser}:{webServerUser} /var/www/html /home/pwadmin", useSudo);
            ExecuteCommand(client, userPassword, "find /var/www/html -type d -exec chmod 755 {} \\;", useSudo);
            ExecuteCommand(client, userPassword, "find /var/www/html -type f -exec chmod 644 {} \\;", useSudo);
            ExecuteCommand(client, userPassword, "chmod +x /home/server /home/chmod.sh", useSudo, true);
        }
        #endregion

        #region --- PW-Panel Installation ---

        /// <summary>
        /// This is the new method to be called by a new "Install Panel" button in your UI.
        /// </summary>
        private async void btnInstallPanel_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(txtHost.Text) ||
                string.IsNullOrWhiteSpace(txtUsername.Text) ||
                string.IsNullOrWhiteSpace(txtPassword.Password))
            {
                MessageBox.Show("Please fill in all SSH connection details.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            btnInstallPanel.IsEnabled = false;
            txtLog.Clear();

            // --- NEW: Prompt user for the credentials file ---
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
                    var connectionInfo = new ConnectionInfo(host, username, new PasswordAuthenticationMethod(username, userPassword));
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
            // --- Sudo Detection Logic ---
            bool useSudo = true;
            try
            {
                var testCmd = client.CreateCommand("sudo -v");
                testCmd.Execute();
                var error = testCmd.Error;
                if (!string.IsNullOrEmpty(error) && error.Contains("sudo: command not found"))
                {
                    useSudo = false;
                }
            }
            catch (Exception)
            {
                useSudo = false;
            }

            Log(useSudo ? "Sudo is available." : "Sudo command not found. Assuming root session.");

            // --- OS Detection and Installation ---
            string osRelease = ExecuteCommand(client, userPassword, "cat /etc/os-release", useSudo);
            if (osRelease.Contains("ID=fedora") || osRelease.Contains("ID_LIKE=rhel"))
            {
                Log("Detected Fedora/RHEL-based system.");
                return InstallPanelOnFedora(client, userPassword, useSudo, dbUser, dbPassword);
            }
            else if (osRelease.Contains("ID=debian") || osRelease.Contains("ID_LIKE=debian") || osRelease.Contains("ID=ubuntu"))
            {
                Log("Detected Debian/Ubuntu-based system.");
                return InstallPanelOnDebian(client, userPassword, useSudo, dbUser, dbPassword);
            }
            else
            {
                throw new Exception("Unsupported OS. Please use a Fedora/RHEL or Debian/Ubuntu based distribution.");
            }
        }

        private string InstallPanelOnDebian(SshClient client, string userPassword, bool useSudo, string dbUser, string dbPassword)
        {
            LogSection("Panel Installation on Debian/Ubuntu");

            // --- Variables for Debian/Ubuntu ---
            string destDir = "/var/www/html";
            string finalDir = "panel";
            string panelDir = $"{destDir}/{finalDir}";
            string apacheDefaultSite = "/etc/apache2/sites-available/000-default.conf";
            string apacheConf = "/etc/apache2/apache2.conf";
            string apacheConfUrl = "http://havenpwi.net/installs/New%20Installer/panel/apache2.conf";

            // 1. Install dependencies and download files
            ExecuteCommand(client, userPassword, "apt-get update -y", useSudo);
            ExecuteCommand(client, userPassword, "apt-get install -y unzip", useSudo);
            DownloadAndExtractPanel(client, userPassword, useSudo, destDir, finalDir);

            // 2. Configure .env
            ConfigurePanelEnvFile(client, userPassword, useSudo, panelDir, dbUser, dbPassword);

            // 3. Install Composer
            InstallComposerOnDebian(client, userPassword, useSudo);

            // 4. Set Permissions
            SetPanelPermissions(client, userPassword, useSudo, panelDir);

            // 5. Database Setup
            DownloadAndImportPanelDb(client, userPassword, useSudo, panelDir, dbUser, dbPassword);

            // 6. Laravel Setup
            RunLaravelSetup(client, userPassword, useSudo, panelDir);

            // 7. Create Admin User and get credentials
            string panelCredentials = CreatePanelAdminUser(client, userPassword, useSudo, panelDir);

            // 8. Configure Apache
            Log("Modifying Apache configuration...");
            ExecuteCommand(client, userPassword, $"wget -q -O {apacheConf} {apacheConfUrl}", useSudo);
            ExecuteCommand(client, userPassword, $"sed -i \"s|DocumentRoot /var/www/html|DocumentRoot /var/www/html/panel/public|\" {apacheDefaultSite}", useSudo, true);
            Log("Enabling mod_rewrite...");
            ExecuteCommand(client, userPassword, "a2enmod rewrite", useSudo);
            Log("Restarting apache2 service...");
            ExecuteCommand(client, userPassword, "systemctl restart apache2", useSudo);

            // 9. Cleanup
            ExecuteCommand(client, userPassword, "rm /tmp/dbo.sql", useSudo);

            return panelCredentials;
        }

        private string InstallPanelOnFedora(SshClient client, string userPassword, bool useSudo, string dbUser, string dbPassword)
        {
            LogSection("Panel Installation on Fedora/RHEL");

            // --- Variables for Fedora/RHEL ---
            string destDir = "/var/www/html";
            string finalDir = "panel";
            string panelDir = $"{destDir}/{finalDir}";
            string apacheConf = "/etc/httpd/conf/httpd.conf";
            string apacheConfUrl = "http://havenpwi.net/installs/New%20Installer/panel/httpd.conf";

            // 1. Install dependencies and download files
            ExecuteCommand(client, userPassword, "dnf check-update -y", useSudo);
            ExecuteCommand(client, userPassword, "dnf install -y unzip composer", useSudo);
            DownloadAndExtractPanel(client, userPassword, useSudo, destDir, finalDir);

            // 2. Configure .env
            ConfigurePanelEnvFile(client, userPassword, useSudo, panelDir, dbUser, dbPassword);

            // 3. Set Permissions
            SetPanelPermissions(client, userPassword, useSudo, panelDir);

            // 4. Database Setup
            DownloadAndImportPanelDb(client, userPassword, useSudo, panelDir, dbUser, dbPassword);

            // 5. Laravel Setup
            RunLaravelSetup(client, userPassword, useSudo, panelDir);

            // 6. Create Admin User
            string panelCredentials = CreatePanelAdminUser(client, userPassword, useSudo, panelDir);

            // 7. Configure Apache
            Log("Modifying Apache configuration...");
            ExecuteCommand(client, userPassword, $"wget -q -O {apacheConf} {apacheConfUrl}", useSudo);
            Log("Restarting httpd service...");
            ExecuteCommand(client, userPassword, "systemctl restart httpd", useSudo);

            // 8. Cleanup
            ExecuteCommand(client, userPassword, "rm /tmp/dbo.sql", useSudo);

            return panelCredentials;
        }

        private void DownloadAndExtractPanel(SshClient client, string userPassword, bool useSudo, string destDir, string finalDir)
        {
            LogSection("Downloading and Extracting Panel Files");
            string sourceUrl = "https://github.com/hrace009/PW-Panel/archive/refs/heads/master.zip";
            string tempZip = "/tmp/panel.zip";
            string extractedDirName = "PW-Panel-master";

            Log("Downloading the ZIP file...");
            ExecuteCommand(client, userPassword, $"wget -q '{sourceUrl}' -O {tempZip}", useSudo);

            Log($"Creating directory: {destDir} if it doesn't exist...");
            ExecuteCommand(client, userPassword, $"mkdir -p {destDir}", useSudo);

            Log($"Extracting the ZIP file to {destDir}...");
            ExecuteCommand(client, userPassword, $"unzip -q -o {tempZip} -d {destDir}", useSudo);

            Log($"Renaming directory to '{finalDir}'...");
            ExecuteCommand(client, userPassword, $"mv {destDir}/{extractedDirName} {destDir}/{finalDir}", useSudo);

            ExecuteCommand(client, userPassword, $"rm {tempZip}", useSudo);
        }

        private void ConfigurePanelEnvFile(SshClient client, string userPassword, bool useSudo, string panelDir, string dbUser, string dbPass)
        {
            LogSection("Configuring .env file");
            string envExampleFile = $"{panelDir}/.env.example";
            string envFile = $"{panelDir}/.env";

            Log($"Updating database settings in {envExampleFile}...");
            ExecuteCommand(client, userPassword, $"sed -i 's/DB_DATABASE=laravel/DB_DATABASE=pw/' {envExampleFile}", useSudo);
            ExecuteCommand(client, userPassword, $"sed -i 's/DB_USERNAME=root/DB_USERNAME={dbUser}/' {envExampleFile}", useSudo);
            ExecuteCommand(client, userPassword, $"sed -i 's/DB_PASSWORD=/DB_PASSWORD={dbPass}/' {envExampleFile}", useSudo);

            Log($"Renaming {envExampleFile} to {envFile}");
            ExecuteCommand(client, userPassword, $"mv {envExampleFile} {envFile}", useSudo);
        }

        private void InstallComposerOnDebian(SshClient client, string userPassword, bool useSudo)
        {
            LogSection("Installing Composer on Debian");
            Log("Checking for existing composer installations...");
            string composerCheck = ExecuteCommand(client, userPassword, "command -v composer", useSudo, true);
            if (!string.IsNullOrWhiteSpace(composerCheck))
            {
                string composerVersion = ExecuteCommand(client, userPassword, "composer --version", useSudo, true);
                if (composerVersion.Contains("Composer version 1."))
                {
                    Log("Composer 1 found, uninstalling...");
                    ExecuteCommand(client, userPassword, "apt-get remove --purge composer -y", useSudo);
                }
                else
                {
                    Log("Composer 2 or newer already installed.");
                    return;
                }
            }

            Log("Downloading Composer installer...");
            string installerUrl = "https://getcomposer.org/installer";
            string installerFile = "/tmp/composer-installer.php";
            ExecuteCommand(client, userPassword, $"wget -q '{installerUrl}' -O {installerFile}", useSudo);

            Log("Running Composer installer...");
            ExecuteCommand(client, userPassword, $"php {installerFile} --install-dir=/usr/local/bin --filename=composer", useSudo);

            ExecuteCommand(client, userPassword, $"rm {installerFile}", useSudo);
        }

        private void SetPanelPermissions(SshClient client, string userPassword, bool useSudo, string panelDir)
        {
            LogSection("Setting Panel Permissions");
            Log("Setting permissions for Laravel directories...");
            ExecuteCommand(client, userPassword, $"cd {panelDir} && chmod -R 777 storage bootstrap app config", useSudo);
        }

        private void DownloadAndImportPanelDb(SshClient client, string userPassword, bool useSudo, string panelDir, string dbUser, string dbPass)
        {
            LogSection("Downloading and Importing Panel Database");
            string sqlFileUrl = "http://havenpwi.net/installs/New%20Installer/panel/dbo.sql";
            string sqlFileLocal = "/tmp/dbo.sql";

            Log("Downloading the SQL file...");
            ExecuteCommand(client, userPassword, $"wget -q '{sqlFileUrl}' -O {sqlFileLocal}", useSudo);

            Log("Importing the SQL file...");
            ExecuteCommand(client, userPassword, $"mysql -u'{dbUser}' -p'{dbPass}' pw < {sqlFileLocal}", useSudo);
        }

        private void RunLaravelSetup(SshClient client, string userPassword, bool useSudo, string panelDir)
        {
            LogSection("Running Laravel Setup");
            string phpPath = "php"; // Assuming php is in the PATH
            string composerPath = "composer"; // Assuming composer is in the PATH

            Log("Running composer install...");
            // Using 'yes' to auto-confirm any prompts.
            ExecuteCommand(client, userPassword, $"cd {panelDir} && yes | {composerPath} install --optimize-autoloader --no-dev", useSudo, false, 600);

            Log("Caching configuration...");
            ExecuteCommand(client, userPassword, $"cd {panelDir} && yes | {phpPath} artisan config:cache", useSudo);

            Log("Running composer install again..."); // As per script
            ExecuteCommand(client, userPassword, $"cd {panelDir} && yes | {composerPath} install", useSudo, false, 600);

            Log("Running database migrations...");
            ExecuteCommand(client, userPassword, $"cd {panelDir} && yes | {phpPath} artisan migrate", useSudo);

            Log("Seeding the database...");
            ExecuteCommand(client, userPassword, $"cd {panelDir} && yes | {phpPath} artisan db:seed --class=ServiceSeeder", useSudo);

            Log("Generating application key...");
            ExecuteCommand(client, userPassword, $"cd {panelDir} && yes | {phpPath} artisan key:generate", useSudo);
        }

        private string CreatePanelAdminUser(SshClient client, string userPassword, bool useSudo, string panelDir)
        {
            LogSection("Creating Panel Admin User");
            string adminUsername = "admin";
            string adminEmail = "randomperson@gmail.com";
            string adminFullname = "randomdev";

            Log("Creating admin user...");
            string command = $"cd {panelDir} && echo -e '{adminUsername}\\n{adminEmail}\\n{adminFullname}\\n' | php artisan pw:createAdmin";
            string adminOutput = ExecuteCommand(client, userPassword, command, useSudo);

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

        private string ExecuteCommand(SshClient client, string password, string command, bool useSudo, bool ignoreErrors = false, int timeoutSeconds = 300)
        {
            string commandToExecute;
            if (useSudo)
            {
                Log($"> sudo {command}");
                // Escape single quotes in the command for bash -c
                string escapedCommand = command.Replace("'", "'\\''");
                commandToExecute = $"echo '{password}' | sudo -S -- bash -c '{escapedCommand}'";
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
            // This method MUST be called from the UI thread.
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