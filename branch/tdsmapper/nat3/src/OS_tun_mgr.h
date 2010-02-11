/* OS_tun_mgr.h

Contains the OS-specfic parts of the tunnel manager. This is a common interface, and both the 
Windows and Linux/BSD tun manager implement this interface.

Arun Madhavan,
Jan 3, 2010
*/

#ifndef __OS_TUN_MGR_H_
#define __OS_TUN_MGR_H_



/* interfaces common to BSD, Linux and Win32 */
HANDLE OS_openTapInterface();


/* Windows-only private functions */
#ifdef _MSC_VER
  #define MAX_KEY_LENGTH 255
  #define MAX_VALUE_NAME 16383
  #define TAP_DEV_CLASS TEXT("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\")
  #define TAP_DEV_NAME  TEXT("tap0801")

  /* TUN/TAP driver redefinitions from tap-win32/constants.h of Windows driver*/
  #define TAP_IOCTL_SET_MEDIA_STATUS 6
  #define TAP_IOCTL_CONFIG_TUN       10 /* To turn TUN/TAP device into TUN mode. Default is TAP mode*/

  /* Search for the TAP device's GUID within this Registry key hKey. */
  bool SearchForDeviceGuid(HKEY hKey, __out TCHAR szGUID[]);
  bool GetDeviceGuid(__out TCHAR guid[]);

  /* Get the Name of the device (eg. Local Area Connection 4) */
  void GetDeviceHumanName(__in TCHAR szGuid[], __out TCHAR szHumanName[]);

  /* Open the TAP interface. Easily modified to open TUN interface*/
  HANDLE OS_openTunTapInterface();

  /* Callbacks for the TAP and ListenFD reads */
  VOID WINAPI TapReadCallback(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap);
  VOID WINAPI ListenFdReadCallback(DWORD dwErr, DWORD cbBytesRead, LPWSAOVERLAPPED lpOverLap, DWORD dwFlags);



#endif /* _MSC_VER */

#endif /* __OS_TUN_MGR_H_ */