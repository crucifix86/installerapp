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