import System.Collections.Generic
import System.Linq
import System.Windows
import System.Windows.Controls
import System.Windows.Data
import System.Windows.Documents
import System.Windows.Media
import System.Windows.Navigation
import System.Windows.Shapes
import System.Windows.Input
import Microsoft.Win32
import Microsoft.Win32
import System.Windows.Input

public __partial class Window1 {

	public init() {

		InitializeComponent()



	}
	private func MainWindow_OnMouseDown(_ sender: Object!, _ e: System.Windows.Input.MouseButtonEventArgs!) {
		if e.ChangedButton == MouseButton.Left {
			DragMove()
		}
	}
	private func Btn_Minimize_Click(_ sender: Object!, _ e: RoutedEventArgs!) {
		super.WindowState = WindowState.Minimized
	}

	private func BtnClose_Click(_ sender: Object!, _ e: RoutedEventArgs!) {
		Close()
	}

	private func Image_Loaded(_ sender: Object!, _ e: RoutedEventArgs!) {
		
		var fullRegLocationPath: String! = ""
		if Environment.Is64BitOperatingSystem {
			fullRegLocationPath = String.Format("HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\{0}", Common.Utility.Constants.RegLocation)
		} else {
			fullRegLocationPath = String.Format("HKEY_LOCAL_MACHINE\\SOFTWARE\\{0}", Common.Utility.Constants.RegLocation)
		}
		var installLocation: String? = (Registry.GetValue(fullRegLocationPath, "InstallLocation", nil) as? String)
		var displayName: String? = (Registry.GetValue(fullRegLocationPath, "DisplayName", nil) as? String)
		if (installLocation == nil) || (displayName == nil) {
			versionLabel.Content = "Currently installed: False"
		} else {
			versionLabel.Content = "Currently installed: True"
			progressBar.Value = 100
		}
		lbl_installedVersion.Content = "2022.01.10"
	}

}