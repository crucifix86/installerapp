using System;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Windows;

namespace installerapp
{
    public static class LocalizationManager
    {
        public static void SetLanguage(string cultureCode)
        {
            try
            {
                var culture = new CultureInfo(cultureCode);
                Thread.CurrentThread.CurrentCulture = culture;
                Thread.CurrentThread.CurrentUICulture = culture;

                // Find and remove the old resource dictionary if it exists
                var oldDict = Application.Current.Resources.MergedDictionaries
                    .FirstOrDefault(d => d.Source != null && d.Source.OriginalString.Contains("String.", StringComparison.OrdinalIgnoreCase));

                if (oldDict != null)
                {
                    Application.Current.Resources.MergedDictionaries.Remove(oldDict);
                }

                var newDict = new ResourceDictionary();

                // CORRECTED LINE: Using an explicit component-relative URI to correctly locate the file inside the Properties folder.
                string uriString = $"/Properties/String.{cultureCode}.xaml";
                newDict.Source = new Uri(uriString, UriKind.Relative);

                Application.Current.Resources.MergedDictionaries.Insert(0, newDict);
            }
            catch (Exception ex)
            {
                // Added the path to the error message for easier debugging if it fails again.
                MessageBox.Show($"Error setting language: {ex.Message}\n\nAttempted to load: {ex.Source}", "Localization Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}