using System.Globalization;
using System.Threading;
using System.Windows;

namespace installerapp
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Set the default language for the application on its first run.
            // A more advanced solution would read this from a saved settings file.
            LocalizationManager.SetLanguage("en-US");
        }
    }
}