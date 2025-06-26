using System;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using Renci.SshNet;
using System.Windows.Controls;
using System.Windows.Input;
using System.Diagnostics;
using Renci.SshNet.Sftp;
using System.Collections.Generic;
using System.Linq;
using Renci.SshNet.Common;
using System.Data;
using System.Data.Common;
using System.Data.SqlClient; // Reverted back to the original SQL client
using MySql.Data.MySqlClient;
using System.Windows.Data;
using System.Globalization;
using System.Threading;
using System.Windows.Navigation;

namespace installerapp
{
    public partial class MainWindow : Window
    {
        private bool _useRoot = false;
        private string _rootPassword = "";
        private bool _useSudo = false;
        private string _privateKeyFilePath = string.Empty;
        private SftpClient? _sftpClient;
        private string _currentRemotePath = "/";
        private FileSystemWatcher? _fileWatcher;
        private string? _localTempFilePath;
        private string? _remoteEditedFilePath;
        private bool _isHandlingDisconnect = false;
        private IDbConnection? _sqlConnection;
        private DbDataAdapter? _sqlDataAdapter;
        private DataTable? _sqlDataTable;


        public MainWindow()
        {
            InitializeComponent();
            cmbVersion.Items.Add("1.5.1");
            cmbVersion.Items.Add("1.5.3");
            cmbVersion.Items.Add("1.5.5");
            cmbVersion.SelectedIndex = 0;
            cmbDbType.SelectedIndex = 0;
            dgSqlResults.CellEditEnding += DgSqlResults_CellEditEnding;
        }

        private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
        {
            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
            e.Handled = true;
        }

        private void cmbLanguage_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (!this.IsLoaded || cmbLanguage.SelectedItem == null) return;

            if (cmbLanguage.SelectedItem is ComboBoxItem selectedItem && selectedItem.Tag is string cultureCode)
            {
                if (Thread.CurrentThread.CurrentUICulture.Name != cultureCode)
                {
                    LocalizationManager.SetLanguage(cultureCode);
                }
            }
        }

        #region --- SFTP Functionality ---
        private async void btnSftpConnect_Click(object sender, RoutedEventArgs e)
        {
            bool useSshKey = chkUseSshKey.IsChecked == true;
            if (string.IsNullOrWhiteSpace(txtHost.Text) || string.IsNullOrWhiteSpace(txtUsername.Text) ||
                (useSshKey && string.IsNullOrWhiteSpace(_privateKeyFilePath)) || (!useSshKey && string.IsNullOrWhiteSpace(txtPassword.Password)))
            {
                MessageBox.Show("Please fill in all required SSH connection details on the Installer tab.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            string host = txtHost.Text;
            string username = txtUsername.Text;
            btnSftpConnect.IsEnabled = false;
            btnSftpDisconnect.IsEnabled = false;

            try
            {
                AuthenticationMethod authMethod;
                if (useSshKey)
                {
                    string keyPassword = txtKeyPassword.Password;
                    var keyFile = string.IsNullOrWhiteSpace(keyPassword)
                        ? new PrivateKeyFile(_privateKeyFilePath)
                        : new PrivateKeyFile(_privateKeyFilePath, keyPassword);
                    authMethod = new PrivateKeyAuthenticationMethod(username, keyFile);
                }
                else
                {
                    authMethod = new PasswordAuthenticationMethod(username, txtPassword.Password);
                }

                var connectionInfo = new ConnectionInfo(host, username, authMethod);
                _sftpClient = new SftpClient(connectionInfo);

                _sftpClient.ErrorOccurred += OnSftpClientError;

                await Task.Run(() => _sftpClient.Connect());

                if (_sftpClient.IsConnected)
                {
                    _isHandlingDisconnect = false;
                    Log("SFTP Connection Successful.");
                    _currentRemotePath = _sftpClient.WorkingDirectory;
                    txtRemotePath.Text = _currentRemotePath;
                    ListRemoteFiles();
                    SetSftpButtonsState(true);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to connect via SFTP: {ex.Message}", "Connection Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                SetSftpButtonsState(false);
            }
        }

        private void btnSftpDisconnect_Click(object sender, RoutedEventArgs e)
        {
            if (_sftpClient != null)
            {
                _sftpClient.ErrorOccurred -= OnSftpClientError;
                if (_sftpClient.IsConnected)
                {
                    _sftpClient.Disconnect();
                }
                _sftpClient.Dispose();
                _sftpClient = null;
            }

            lvFiles.ItemsSource = null;
            txtRemotePath.Text = "";
            Log("SFTP Disconnected.");
            SetSftpButtonsState(false);
        }

        private void OnSftpClientError(object? sender, ExceptionEventArgs e)
        {
            if (_isHandlingDisconnect || _sftpClient == null || !_sftpClient.IsConnected)
            {
                return;
            }
            _isHandlingDisconnect = true;

            Dispatcher.BeginInvoke(new Action(() =>
            {
                try
                {
                    Log("SFTP connection was lost. Please reconnect manually.");
                    btnSftpDisconnect_Click(this, new RoutedEventArgs());
                }
                finally
                {
                    _isHandlingDisconnect = false;
                }
            }));
        }


        private void SetSftpButtonsState(bool connected)
        {
            btnSftpConnect.IsEnabled = !connected;
            btnSftpDisconnect.IsEnabled = connected;
            btnSftpUpload.IsEnabled = connected;
            btnSftpDownload.IsEnabled = connected;
            btnSftpEdit.IsEnabled = connected;
            btnNewFile.IsEnabled = connected;
            btnNewFolder.IsEnabled = connected;
        }

        private void ListRemoteFiles(string? path = null)
        {
            if (_sftpClient?.IsConnected != true) return;
            try
            {
                _currentRemotePath = path ?? _currentRemotePath;
                if (string.IsNullOrEmpty(_currentRemotePath)) _currentRemotePath = "/";
                txtRemotePath.Text = _currentRemotePath;

                var files = _sftpClient.ListDirectory(_currentRemotePath);
                var fileList = new List<SftpFile>();

                if (_currentRemotePath != "/")
                {
                    var parentFullName = Path.GetDirectoryName(_currentRemotePath.TrimEnd('/'))?.Replace("\\", "/") ?? "/";
                    if (string.IsNullOrEmpty(parentFullName)) parentFullName = "/";
                    fileList.Add(new SftpFile { Name = "..", FullName = parentFullName, IsDirectory = true, Permissions = "dr-xr-xr-x" });
                }

                fileList.AddRange(files
                    .Where(f => f.Name != "." && f.Name != "..")
                    .Select(f => new SftpFile
                    {
                        Name = f.Name,
                        FullName = f.FullName,
                        IsDirectory = f.IsDirectory,
                        Length = f.Length,
                        LastWriteTime = f.LastWriteTime,
                        Permissions = FormatPermissions(f.Attributes)
                    }));

                lvFiles.ItemsSource = fileList.OrderByDescending(f => f.IsDirectory).ThenBy(f => f.Name);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error listing files: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string FormatPermissions(SftpFileAttributes attributes)
        {
            var sb = new System.Text.StringBuilder();
            sb.Append(attributes.IsDirectory ? 'd' : '-');
            sb.Append(attributes.OwnerCanRead ? 'r' : '-');
            sb.Append(attributes.OwnerCanWrite ? 'w' : '-');
            sb.Append(attributes.OwnerCanExecute ? 'x' : '-');
            sb.Append(attributes.GroupCanRead ? 'r' : '-');
            sb.Append(attributes.GroupCanWrite ? 'w' : '-');
            sb.Append(attributes.GroupCanExecute ? 'x' : '-');
            sb.Append(attributes.OthersCanRead ? 'r' : '-');
            sb.Append(attributes.OthersCanWrite ? 'w' : '-');
            sb.Append(attributes.OthersCanExecute ? 'x' : '-');
            return sb.ToString();
        }

        private int GetPermissionsAsInt(SftpFileAttributes attributes)
        {
            int mode = 0;
            if (attributes.OwnerCanRead) mode |= 256;
            if (attributes.OwnerCanWrite) mode |= 128;
            if (attributes.OwnerCanExecute) mode |= 64;
            if (attributes.GroupCanRead) mode |= 32;
            if (attributes.GroupCanWrite) mode |= 16;
            if (attributes.GroupCanExecute) mode |= 8;
            if (attributes.OthersCanRead) mode |= 4;
            if (attributes.OthersCanWrite) mode |= 2;
            if (attributes.OthersCanExecute) mode |= 1;
            return mode;
        }

        private void lvFiles_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            if (lvFiles.SelectedItem is SftpFile file && file.IsDirectory)
            {
                ListRemoteFiles(file.FullName);
            }
        }

        private void btnNewFolder_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new InputDialog("Create New Folder", "Enter folder name:");
            if (dialog.ShowDialog() == true && _sftpClient != null)
            {
                string folderName = dialog.InputText;
                if (string.IsNullOrWhiteSpace(folderName)) return;

                string newFolderPath = Path.Combine(_currentRemotePath, folderName).Replace("\\", "/");
                try
                {
                    _sftpClient.CreateDirectory(newFolderPath);
                    Log($"Folder '{folderName}' created.");
                    ListRemoteFiles();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to create folder: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void btnNewFile_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new InputDialog("Create New File", "Enter file name:");
            if (dialog.ShowDialog() == true && _sftpClient != null)
            {
                string fileName = dialog.InputText;
                if (string.IsNullOrWhiteSpace(fileName)) return;

                string newFilePath = Path.Combine(_currentRemotePath, fileName).Replace("\\", "/");
                try
                {
                    using (var stream = new MemoryStream())
                    {
                        _sftpClient.UploadFile(stream, newFilePath);
                    }
                    Log($"File '{fileName}' created.");
                    ListRemoteFiles();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to create file: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void PermissionsMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (lvFiles.SelectedItem is not SftpFile selectedFile || selectedFile.Name == ".." || _sftpClient == null) return;

            try
            {
                var attributes = _sftpClient.GetAttributes(selectedFile.FullName);
                var currentPermissions = GetPermissionsAsInt(attributes);
                var dialog = new PermissionsDialog(currentPermissions);

                if (dialog.ShowDialog() == true)
                {
                    var newPermissions = dialog.Permissions;

                    attributes.OwnerCanRead = (newPermissions & 256) != 0;
                    attributes.OwnerCanWrite = (newPermissions & 128) != 0;
                    attributes.OwnerCanExecute = (newPermissions & 64) != 0;

                    attributes.GroupCanRead = (newPermissions & 32) != 0;
                    attributes.GroupCanWrite = (newPermissions & 16) != 0;
                    attributes.GroupCanExecute = (newPermissions & 8) != 0;

                    attributes.OthersCanRead = (newPermissions & 4) != 0;
                    attributes.OthersCanWrite = (newPermissions & 2) != 0;
                    attributes.OthersCanExecute = (newPermissions & 1) != 0;

                    _sftpClient.SetAttributes(selectedFile.FullName, attributes);

                    Log($"Permissions changed for '{selectedFile.Name}'.");
                    ListRemoteFiles();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to set permissions: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void DeleteMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (lvFiles.SelectedItem is not SftpFile selectedFile || selectedFile.Name == ".." || _sftpClient == null)
            {
                MessageBox.Show("Please select a file or directory to delete.", "Selection Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var result = MessageBox.Show($"Are you sure you want to delete '{selectedFile.Name}'?", "Confirm Delete", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    if (selectedFile.IsDirectory)
                    {
                        _sftpClient.DeleteDirectory(selectedFile.FullName);
                        Log($"Deleted directory '{selectedFile.Name}'.");
                    }
                    else
                    {
                        _sftpClient.DeleteFile(selectedFile.FullName);
                        Log($"Deleted file '{selectedFile.Name}'.");
                    }
                    ListRemoteFiles();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Delete failed: {ex.Message}. Note: Directories must be empty.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void btnSftpUpload_Click(object sender, RoutedEventArgs e)
        {
            if (_sftpClient?.IsConnected != true) return;
            var openFileDialog = new OpenFileDialog { Title = "Select File to Upload", Filter = "All files (*.*)|*.*" };
            if (openFileDialog.ShowDialog() == true)
            {
                try
                {
                    string localPath = openFileDialog.FileName;
                    string remotePath = Path.Combine(_currentRemotePath, Path.GetFileName(localPath)).Replace("\\", "/");
                    using (var fileStream = new FileStream(localPath, FileMode.Open))
                    {
                        _sftpClient.UploadFile(fileStream, remotePath);
                    }
                    Log($"Uploaded '{Path.GetFileName(localPath)}' to '{_currentRemotePath}'.");
                    ListRemoteFiles();
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Upload failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void btnSftpDownload_Click(object sender, RoutedEventArgs e)
        {
            if (lvFiles.SelectedItem is not SftpFile selectedFile || selectedFile.IsDirectory || _sftpClient == null)
            {
                MessageBox.Show("Please select a file to download.", "Selection Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            var saveFileDialog = new SaveFileDialog { Title = "Save File As", FileName = selectedFile.Name };
            if (saveFileDialog.ShowDialog() == true)
            {
                try
                {
                    using (var fileStream = new FileStream(saveFileDialog.FileName, FileMode.Create))
                    {
                        _sftpClient.DownloadFile(selectedFile.FullName, fileStream);
                    }
                    Log($"Downloaded '{selectedFile.Name}' to '{saveFileDialog.FileName}'.");
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Download failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void btnSftpEdit_Click(object sender, RoutedEventArgs e)
        {
            if (lvFiles.SelectedItem is not SftpFile selectedFile || selectedFile.IsDirectory || _sftpClient == null)
            {
                MessageBox.Show("Please select a file to edit.", "Selection Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string? notepadPlusPlusPath = FindNotepadPlusPlus();
            if (string.IsNullOrEmpty(notepadPlusPlusPath))
            {
                var result = MessageBox.Show("Notepad++ not found. Would you like to download it from https://notepad-plus-plus.org/downloads/ ?", "Notepad++ Not Found", MessageBoxButton.YesNo, MessageBoxImage.Question);
                if (result == MessageBoxResult.Yes)
                {
                    Process.Start(new ProcessStartInfo("https://notepad-plus-plus.org/downloads/") { UseShellExecute = true });
                }
                return;
            }

            try
            {
                _localTempFilePath = Path.Combine(Path.GetTempPath(), selectedFile.Name);
                _remoteEditedFilePath = selectedFile.FullName;
                using (var fileStream = new FileStream(_localTempFilePath, FileMode.Create, FileAccess.Write))
                {
                    _sftpClient.DownloadFile(_remoteEditedFilePath, fileStream);
                }

                _fileWatcher = new FileSystemWatcher(Path.GetTempPath())
                {
                    Filter = Path.GetFileName(_localTempFilePath),
                    NotifyFilter = NotifyFilters.LastWrite,
                    EnableRaisingEvents = true
                };
                _fileWatcher.Changed += OnTempFileChanged;

                Process.Start(notepadPlusPlusPath, $"\"{_localTempFilePath}\"");
                Log($"Opening '{selectedFile.Name}' for editing. Save the file in Notepad++ to upload changes.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to open file for editing: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string? FindNotepadPlusPlus()
        {
            var possiblePaths = new List<string?>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
            };

            foreach (string? path in possiblePaths.Distinct())
            {
                if (string.IsNullOrEmpty(path)) continue;
                string notepadPlusPlusPath = Path.Combine(path, "Notepad++", "notepad++.exe");
                if (File.Exists(notepadPlusPlusPath))
                {
                    return notepadPlusPlusPath;
                }
            }
            return null;
        }

        private void OnTempFileChanged(object sender, FileSystemEventArgs e)
        {
            if (e.ChangeType != WatcherChangeTypes.Changed || _sftpClient == null) return;
            Dispatcher.Invoke(() =>
            {
                try
                {
                    if (_fileWatcher != null)
                    {
                        _fileWatcher.EnableRaisingEvents = false;
                    }
                    if (_localTempFilePath != null && _remoteEditedFilePath != null)
                    {
                        using (var fileStream = new FileStream(_localTempFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        {
                            _sftpClient.UploadFile(fileStream, _remoteEditedFilePath);
                        }
                        Log($"File '{Path.GetFileName(_remoteEditedFilePath)}' was updated on the server.");
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to upload changes for '{Path.GetFileName(_remoteEditedFilePath)}': {ex.Message}", "Upload Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                finally
                {
                    if (_fileWatcher != null)
                    {
                        _fileWatcher.Changed -= OnTempFileChanged;
                        _fileWatcher.Dispose();
                        _fileWatcher = null;
                    }
                    if (_localTempFilePath != null)
                    {
                        try { File.Delete(_localTempFilePath); }
                        catch (Exception ex) { Log($"Could not delete temp file '{_localTempFilePath}': {ex.Message}"); }
                    }
                }
            });
        }

        private void btnBrowseKey_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog { Title = "Select Private Key File", Filter = "All files (*.*)|*.*" };
            if (openFileDialog.ShowDialog() == true)
            {
                _privateKeyFilePath = openFileDialog.FileName;
                txtKeyPath.Text = _privateKeyFilePath;
            }
        }

        private void chkUseSshKey_Checked(object sender, RoutedEventArgs e) { }
        #endregion

        #region --- SQL Database Functionality ---
        private void btnSqlConnection_Click(object sender, RoutedEventArgs e)
        {
            string? dbType = (cmbDbType.SelectedItem as ComboBoxItem)?.Content.ToString();
            string server = txtSqlServer.Text;
            string port = txtSqlPort.Text;
            string database = txtSqlDatabase.Text;
            string userId = txtSqlUser.Text;
            string password = txtSqlPassword.Password;

            if (string.IsNullOrWhiteSpace(server) || string.IsNullOrWhiteSpace(database) || string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(dbType))
            {
                MessageBox.Show("Please fill in all SQL connection details, including the database type.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            string connectionString;

            try
            {
                if (dbType == "SQL Server")
                {
                    string serverAndPort = server;
                    if (!string.IsNullOrWhiteSpace(port))
                    {
                        serverAndPort += "," + port;
                    }
                    connectionString = $"Server={serverAndPort};Database={database};User Id={userId};Password={password};TrustServerCertificate=True;";
                    _sqlConnection = new SqlConnection(connectionString);
                }
                else // MariaDB/MySQL
                {
                    connectionString = $"Server={server};Port={port};Database={database};Uid={userId};Pwd={password};";
                    _sqlConnection = new MySqlConnection(connectionString);
                }

                _sqlConnection.Open();
                Log("SQL Connection Successful.");
                btnSqlConnection.IsEnabled = false;
                btnSqlDisconnect.IsEnabled = true;
                btnExecuteSql.IsEnabled = true;
                btnRefreshTables.IsEnabled = true;
                btnNewTable.IsEnabled = true;
                RefreshTableList();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to connect to the database: {ex.Message}", "Connection Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                btnSqlConnection.IsEnabled = true;
                btnSqlDisconnect.IsEnabled = false;
                btnExecuteSql.IsEnabled = false;
                btnRefreshTables.IsEnabled = false;
                btnNewTable.IsEnabled = false;
            }
        }

        private void btnSqlDisconnect_Click(object sender, RoutedEventArgs e)
        {
            if (_sqlConnection?.State == ConnectionState.Open)
            {
                _sqlConnection.Close();
                _sqlConnection.Dispose();
                _sqlConnection = null;
            }
            Log("SQL Disconnected.");
            btnSqlConnection.IsEnabled = true;
            btnSqlDisconnect.IsEnabled = false;
            btnExecuteSql.IsEnabled = false;
            btnRefreshTables.IsEnabled = false;
            btnNewTable.IsEnabled = false;
            lvTables.ItemsSource = null;
            dgSqlResults.ItemsSource = null;
        }

        private void DgSqlResults_CellEditEnding(object? sender, DataGridCellEditEndingEventArgs e)
        {
            if (e.EditAction == DataGridEditAction.Commit)
            {
                try
                {
                    if (_sqlDataAdapter != null && _sqlDataTable != null)
                    {
                        (e.Row.Item as DataRowView)?.EndEdit();

                        if (_sqlDataAdapter is SqlDataAdapter sqlAdapter)
                        {
                            new SqlCommandBuilder(sqlAdapter);
                            sqlAdapter.Update(_sqlDataTable);
                        }
                        else if (_sqlDataAdapter is MySqlDataAdapter mySqlAdapter)
                        {
                            new MySqlCommandBuilder(mySqlAdapter);
                            mySqlAdapter.Update(_sqlDataTable);
                        }
                        Log("Changes saved to the database.");
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to save changes: {ex.Message}", "Update Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                    if (lvTables.SelectedItem is string tableName)
                    {
                        string query = _sqlConnection is SqlConnection ? $"SELECT * FROM [{tableName}]" : $"SELECT * FROM `{tableName}`";
                        ExecuteQuery(query);
                    }
                }
            }
        }

        private void ExecuteQuery(string query)
        {
            if (_sqlConnection?.State != ConnectionState.Open)
            {
                MessageBox.Show("Not connected to a database.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (string.IsNullOrWhiteSpace(query))
            {
                MessageBox.Show("SQL query cannot be empty.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            try
            {
                if (query.Trim().StartsWith("SELECT", StringComparison.OrdinalIgnoreCase))
                {
                    if (_sqlConnection is SqlConnection sqlConn)
                    {
                        _sqlDataAdapter = new SqlDataAdapter(query, sqlConn);
                    }
                    else if (_sqlConnection is MySqlConnection mySqlConn)
                    {
                        _sqlDataAdapter = new MySqlDataAdapter(query, mySqlConn);
                    }
                    else
                    {
                        MessageBox.Show("Unsupported database connection type.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }

                    _sqlDataTable = new DataTable();
                    _sqlDataAdapter.Fill(_sqlDataTable);
                    dgSqlResults.ItemsSource = _sqlDataTable.DefaultView;
                    dgSqlResults.IsReadOnly = false;
                    Log($"Executed query: {query}");
                }
                else
                {
                    using (var cmd = _sqlConnection.CreateCommand())
                    {
                        cmd.CommandText = query;
                        int recordsAffected = cmd.ExecuteNonQuery();
                        Log($"Executed non-query. {recordsAffected} records affected. Query: {query}");
                        dgSqlResults.ItemsSource = null;
                        dgSqlResults.IsReadOnly = true;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error executing query: {ex.Message}", "Query Failed", MessageBoxButton.OK, MessageBoxImage.Error);
                dgSqlResults.IsReadOnly = true;
            }
        }

        private void btnExecuteSql_Click(object sender, RoutedEventArgs e)
        {
            ExecuteQuery(txtSqlQuery.Text);
        }

        private void RefreshTableList()
        {
            if (_sqlConnection?.State != ConnectionState.Open) return;

            try
            {
                DataTable? schema = null;
                if (_sqlConnection is SqlConnection sqlConnection)
                {
                    schema = sqlConnection.GetSchema("Tables");
                }
                else if (_sqlConnection is MySqlConnection mySqlConnection)
                {
                    schema = mySqlConnection.GetSchema("Tables");
                }

                if (schema != null)
                {
                    var tables = new List<string>();
                    foreach (DataRow row in schema.Rows)
                    {
                        tables.Add(row["TABLE_NAME"].ToString() ?? string.Empty);
                    }
                    lvTables.ItemsSource = tables.OrderBy(t => t);
                    Log("Table list refreshed.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to retrieve table list: " + ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void btnRefreshTables_Click(object sender, RoutedEventArgs e)
        {
            RefreshTableList();
        }

        private void lvTables_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (lvTables.SelectedItem is string tableName)
            {
                string query = $"SELECT * FROM `{tableName}`";
                if (_sqlConnection is SqlConnection)
                {
                    query = $"SELECT * FROM [{tableName}]";
                }
                txtSqlQuery.Text = query;
                ExecuteQuery(query);
            }
        }

        private void ViewTableDataMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (lvTables.SelectedItem is string tableName)
            {
                string query = $"SELECT * FROM `{tableName}`";
                if (_sqlConnection is SqlConnection)
                {
                    query = $"SELECT * FROM [{tableName}]";
                }
                txtSqlQuery.Text = query;
                ExecuteQuery(query);
            }
        }

        private void DropTableMenuItem_Click(object sender, RoutedEventArgs e)
        {
            if (lvTables.SelectedItem is string tableName)
            {
                var result = MessageBox.Show($"Are you sure you want to permanently delete the table '{tableName}'?", "Confirm Drop Table", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result == MessageBoxResult.Yes)
                {
                    string query = $"DROP TABLE `{tableName}`";
                    if (_sqlConnection is SqlConnection)
                    {
                        query = $"DROP TABLE [{tableName}]";
                    }
                    ExecuteQuery(query);
                    RefreshTableList();
                }
            }
        }

        private void btnNewTable_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new CreateTableDialog();
            if (dialog.ShowDialog() == true)
            {
                string tableName = dialog.TableName;
                var columns = dialog.Columns.Where(c => !string.IsNullOrWhiteSpace(c.Name) && !string.IsNullOrWhiteSpace(c.DataType)).ToList();
                if (string.IsNullOrWhiteSpace(tableName) || !columns.Any())
                {
                    MessageBox.Show("Table name and at least one valid column (with name and data type) are required.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                var columnDefinitions = columns.Select(c => $"`{c.Name}` {c.DataType}" + (c.IsPrimaryKey ? " PRIMARY KEY" : ""));
                string query = $"CREATE TABLE `{tableName}` ({string.Join(", ", columnDefinitions)})";

                if (_sqlConnection is SqlConnection)
                {
                    columnDefinitions = columns.Select(c => $"[{c.Name}] {c.DataType}" + (c.IsPrimaryKey ? " PRIMARY KEY" : ""));
                    query = $"CREATE TABLE [{tableName}] ({string.Join(", ", columnDefinitions)})";
                }

                ExecuteQuery(query);
                RefreshTableList();
            }
        }
        #endregion

        #region --- Core Logic and Installation Steps ---
        private async void btnInstall_Click(object sender, RoutedEventArgs e)
        {
            bool useSshKey = chkUseSshKey.IsChecked == true;
            if (string.IsNullOrWhiteSpace(txtHost.Text) || string.IsNullOrWhiteSpace(txtUsername.Text) || (useSshKey && string.IsNullOrWhiteSpace(_privateKeyFilePath)))
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
            string userPassword = txtPassword.Password;
            string? version = cmbVersion.SelectedItem?.ToString();
            if (version == null)
            {
                MessageBox.Show("Please select a server version.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Error);
                btnInstall.IsEnabled = true;
                return;
            }
            string dbPassword = string.IsNullOrWhiteSpace(txtDbPassword.Text) ? Path.GetRandomFileName().Replace(".", "").Substring(0, 10) : txtDbPassword.Text;

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

                    using (var client = new SshClient(new ConnectionInfo(host, username, authMethod)))
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
                case "1.5.1":
                case "1.5.5":
                    sqlUrl = "http://havenpwi.net/install2/Installer/155/pwa.sql";
                    sqlFile = "pwa.sql";
                    break;
            }
            string localSqlPath = $"/tmp/{sqlFile}";
            Log($"Downloading database file {sqlFile} for version {version}...");
            ExecuteCommand(client, userPassword, $"wget -O {localSqlPath} {sqlUrl}");

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
            bool useSshKey = chkUseSshKey.IsChecked == true;

            if (string.IsNullOrWhiteSpace(txtHost.Text) || string.IsNullOrWhiteSpace(txtUsername.Text) || (useSshKey && string.IsNullOrWhiteSpace(_privateKeyFilePath)))
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
            string? panelCredentials = null;

            try
            {
                Log("--- Starting PW-Panel Installation ---");
                Log($"Read credentials from '{Path.GetFileName(filePath)}': User='{dbUser}'");

                panelCredentials = await Task.Run<string?>(() =>
                {
                    AuthenticationMethod authMethod;
                    if (useSshKey)
                    {
                        Log("Attempting authentication using SSH key.");
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
            Dispatcher.Invoke(() =>
            {
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

            using (var cmd = client.CreateCommand(commandToExecute))
            {
                cmd.CommandTimeout = TimeSpan.FromSeconds(timeoutSeconds);
                var result = cmd.Execute();
                string stderr;
                using (var reader = new StreamReader(cmd.ExtendedOutputStream))
                {
                    stderr = reader.ReadToEnd();
                }

                if (!string.IsNullOrWhiteSpace(stderr)) Log($"STDERR: {stderr}");
                if (cmd.ExitStatus != 0 && !ignoreErrors) throw new Exception($"Command failed with exit code {cmd.ExitStatus}.\nError: {stderr}\nCommand: {command}");
                return result;
            }
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

    #region --- Helper Classes for Dialogs and SFTP items ---
    public class SftpFile
    {
        public string Name { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public bool IsDirectory { get; set; }
        public long Length { get; set; }
        public DateTime LastWriteTime { get; set; }
        public string Permissions { get; set; } = string.Empty;
        public string Size => IsDirectory ? "<DIR>" : $"{Math.Round(Length / 1024.0, 2)} KB";
    }

    public class InputDialog : Window
    {
        public string InputText { get; private set; }
        private readonly TextBox _textBox;

        public InputDialog(string title, string prompt)
        {
            Title = title;
            Width = 300;
            Height = 150;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            var mainPanel = new StackPanel { Margin = new Thickness(10) };
            mainPanel.Children.Add(new TextBlock { Text = prompt, Margin = new Thickness(0, 0, 0, 5) });
            _textBox = new TextBox { Margin = new Thickness(0, 0, 0, 10) };
            mainPanel.Children.Add(_textBox);
            var buttonPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            var okButton = new Button { Content = "OK", IsDefault = true, Width = 75, Margin = new Thickness(5) };
            okButton.Click += (s, e) => { InputText = _textBox.Text; DialogResult = true; };
            var cancelButton = new Button { Content = "Cancel", IsCancel = true, Width = 75, Margin = new Thickness(5) };
            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            Content = mainPanel;
            InputText = string.Empty;
        }
    }

    public class PermissionsDialog : Window
    {
        public int Permissions { get; private set; }
        private readonly CheckBox _ownerRead, _ownerWrite, _ownerExecute;
        private readonly CheckBox _groupRead, _groupWrite, _groupExecute;
        private readonly CheckBox _otherRead, _otherWrite, _otherExecute;
        private readonly TextBlock _octalTextBlock;

        public PermissionsDialog(int initialPermissions)
        {
            Title = "Set Permissions";
            Width = 350;
            Height = 280;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            var mainPanel = new StackPanel { Margin = new Thickness(15) };
            mainPanel.Children.Add(new TextBlock { Text = "Permissions", FontWeight = FontWeights.Bold, Margin = new Thickness(0, 0, 0, 10) });

            var grid = new Grid();
            for (int i = 0; i < 4; i++) grid.ColumnDefinitions.Add(new ColumnDefinition());
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            grid.Children.Add(new TextBlock { Text = "Read", HorizontalAlignment = HorizontalAlignment.Center });
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 0); Grid.SetColumn(grid.Children[grid.Children.Count - 1], 1);
            grid.Children.Add(new TextBlock { Text = "Write", HorizontalAlignment = HorizontalAlignment.Center });
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 0); Grid.SetColumn(grid.Children[grid.Children.Count - 1], 2);
            grid.Children.Add(new TextBlock { Text = "Execute", HorizontalAlignment = HorizontalAlignment.Center });
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 0); Grid.SetColumn(grid.Children[grid.Children.Count - 1], 3);

            grid.Children.Add(new TextBlock { Text = "Owner:", VerticalAlignment = VerticalAlignment.Center });
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 1);
            _ownerRead = new CheckBox { IsChecked = (initialPermissions & 256) != 0, HorizontalAlignment = HorizontalAlignment.Center };
            _ownerRead.Click += OnPermissionChanged;
            grid.Children.Add(_ownerRead);
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 1); Grid.SetColumn(grid.Children[grid.Children.Count - 1], 1);
            _ownerWrite = new CheckBox { IsChecked = (initialPermissions & 128) != 0, HorizontalAlignment = HorizontalAlignment.Center };
            _ownerWrite.Click += OnPermissionChanged;
            grid.Children.Add(_ownerWrite);
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 1); Grid.SetColumn(grid.Children[grid.Children.Count - 1], 2);
            _ownerExecute = new CheckBox { IsChecked = (initialPermissions & 64) != 0, HorizontalAlignment = HorizontalAlignment.Center };
            _ownerExecute.Click += OnPermissionChanged;
            grid.Children.Add(_ownerExecute);
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 1); Grid.SetColumn(grid.Children[grid.Children.Count - 1], 3);

            grid.Children.Add(new TextBlock { Text = "Group:", VerticalAlignment = VerticalAlignment.Center });
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 2);
            _groupRead = new CheckBox { IsChecked = (initialPermissions & 32) != 0, HorizontalAlignment = HorizontalAlignment.Center };
            _groupRead.Click += OnPermissionChanged;
            grid.Children.Add(_groupRead);
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 2); Grid.SetColumn(grid.Children[grid.Children.Count - 1], 1);
            _groupWrite = new CheckBox { IsChecked = (initialPermissions & 16) != 0, HorizontalAlignment = HorizontalAlignment.Center };
            _groupWrite.Click += OnPermissionChanged;
            grid.Children.Add(_groupWrite);
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 2); Grid.SetColumn(grid.Children[grid.Children.Count - 1], 2);
            _groupExecute = new CheckBox { IsChecked = (initialPermissions & 8) != 0, HorizontalAlignment = HorizontalAlignment.Center };
            _groupExecute.Click += OnPermissionChanged;
            grid.Children.Add(_groupExecute);
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 2); Grid.SetColumn(grid.Children[grid.Children.Count - 1], 3);

            grid.Children.Add(new TextBlock { Text = "Other:", VerticalAlignment = VerticalAlignment.Center });
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 3);
            _otherRead = new CheckBox { IsChecked = (initialPermissions & 4) != 0, HorizontalAlignment = HorizontalAlignment.Center };
            _otherRead.Click += OnPermissionChanged;
            grid.Children.Add(_otherRead);
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 3); Grid.SetColumn(grid.Children[grid.Children.Count - 1], 1);
            _otherWrite = new CheckBox { IsChecked = (initialPermissions & 2) != 0, HorizontalAlignment = HorizontalAlignment.Center };
            _otherWrite.Click += OnPermissionChanged;
            grid.Children.Add(_otherWrite);
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 3); Grid.SetColumn(grid.Children[grid.Children.Count - 1], 2);
            _otherExecute = new CheckBox { IsChecked = (initialPermissions & 1) != 0, HorizontalAlignment = HorizontalAlignment.Center };
            _otherExecute.Click += OnPermissionChanged;
            grid.Children.Add(_otherExecute);
            Grid.SetRow(grid.Children[grid.Children.Count - 1], 3); Grid.SetColumn(grid.Children[grid.Children.Count - 1], 3);

            mainPanel.Children.Add(grid);

            _octalTextBlock = new TextBlock { Margin = new Thickness(0, 15, 0, 0), HorizontalAlignment = HorizontalAlignment.Center, FontWeight = FontWeights.Bold, FontSize = 14 };
            mainPanel.Children.Add(_octalTextBlock);

            var buttonPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 15, 0, 0) };
            var okButton = new Button { Content = "OK", IsDefault = true, Width = 75, Margin = new Thickness(5) };
            okButton.Click += (s, e) => { DialogResult = true; };
            var cancelButton = new Button { Content = "Cancel", IsCancel = true, Width = 75, Margin = new Thickness(5) };
            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            mainPanel.Children.Add(buttonPanel);

            Content = mainPanel;

            UpdatePermissions();
        }

        private void OnPermissionChanged(object sender, RoutedEventArgs e)
        {
            UpdatePermissions();
        }

        private void UpdatePermissions()
        {
            Permissions = (_ownerRead.IsChecked == true ? 256 : 0) | (_ownerWrite.IsChecked == true ? 128 : 0) | (_ownerExecute.IsChecked == true ? 64 : 0) |
                          (_groupRead.IsChecked == true ? 32 : 0) | (_groupWrite.IsChecked == true ? 16 : 0) | (_groupExecute.IsChecked == true ? 8 : 0) |
                          (_otherRead.IsChecked == true ? 4 : 0) | (_otherWrite.IsChecked == true ? 2 : 0) | (_otherExecute.IsChecked == true ? 1 : 0);

            _octalTextBlock.Text = $"Octal Value: {Convert.ToString(Permissions, 8).PadLeft(3, '0')}";
        }
    }

    public class CreateTableDialog : Window
    {
        public string TableName { get; private set; }
        public List<ColumnInfo> Columns { get; private set; }

        private readonly TextBox _tableNameTextBox;
        private readonly DataGrid _columnsGrid;
        private readonly List<string> _dataTypes = new List<string>
        {
            "INT", "VARCHAR(255)", "TEXT", "DATE", "DATETIME", "TIMESTAMP", "DECIMAL(10, 2)", "FLOAT", "BOOL", "BLOB"
        };

        public CreateTableDialog()
        {
            Title = "Create New Table";
            Width = 450;
            Height = 350;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;

            var mainPanel = new StackPanel { Margin = new Thickness(10) };

            mainPanel.Children.Add(new TextBlock { Text = "Table Name:" });
            _tableNameTextBox = new TextBox { Margin = new Thickness(0, 0, 0, 10) };
            mainPanel.Children.Add(_tableNameTextBox);

            _columnsGrid = new DataGrid
            {
                AutoGenerateColumns = false,
                CanUserAddRows = true,
                ItemsSource = new List<ColumnInfo> { new ColumnInfo { DataType = _dataTypes.First() } }
            };

            var nameCol = new DataGridTextColumn { Header = "Column Name", Binding = new Binding("Name"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) };
            var typeCol = new DataGridComboBoxColumn
            {
                Header = "Data Type",
                ItemsSource = _dataTypes,
                SelectedValueBinding = new Binding("DataType"),
                Width = new DataGridLength(1, DataGridLengthUnitType.Star)
            };
            var pkCol = new DataGridCheckBoxColumn { Header = "Primary Key", Binding = new Binding("IsPrimaryKey") };

            _columnsGrid.Columns.Add(nameCol);
            _columnsGrid.Columns.Add(typeCol);
            _columnsGrid.Columns.Add(pkCol);

            mainPanel.Children.Add(_columnsGrid);

            var buttonPanel = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
            var okButton = new Button { Content = "OK", IsDefault = true, Width = 75, Margin = new Thickness(5) };
            okButton.Click += (s, e) =>
            {
                TableName = _tableNameTextBox.Text;
                Columns = (List<ColumnInfo>)_columnsGrid.ItemsSource;
                DialogResult = true;
            };
            var cancelButton = new Button { Content = "Cancel", IsCancel = true, Width = 75, Margin = new Thickness(5) };
            buttonPanel.Children.Add(okButton);
            buttonPanel.Children.Add(cancelButton);
            mainPanel.Children.Add(buttonPanel);

            Content = mainPanel;

            TableName = string.Empty;
            Columns = new List<ColumnInfo>();
        }
    }

    public class ColumnInfo
    {
        public string Name { get; set; } = string.Empty;
        public string DataType { get; set; } = string.Empty;
        public bool IsPrimaryKey { get; set; }
    }
    #endregion
}