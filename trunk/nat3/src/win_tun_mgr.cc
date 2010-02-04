/* Windows specific interface implementations of tunnel manager. Interface defined by OS_tun_mgr.h*/

#ifdef _MSC_VER

#include <Winsock2.h>
#include <WinDef.h>
#include <Windows.h>
#include <string>
#include <winnt.h>
#include <iostream>
#include <tchar.h>
#include <strsafe.h>
#include <assert.h>


#include "OS_tun_mgr.h"
#include "types.h"
#include "tun_mgr.h"
#include "tun_defs.h"
#include "tun_in_ent.h"
#include "tun_out_ent.h"
#include "functions.h"

void OS_init(HANDLE *m_hTunFd, SOCKET *m_sListenFd)
{

  
}

/* Search for the TAP device's GUID within this Registry key hKey. */
bool SearchForDeviceGuid(HKEY hKey, __out TCHAR szGUID[]) 
{ 
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys=0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	FILETIME ftLastWriteTime;      // last write time 

	bool bRet = false;
	DWORD retCode; 

	DWORD cchValue = MAX_VALUE_NAME; 

	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

	// Enumerate the subkeys, until RegEnumKeyEx fails.
	if (cSubKeys)
	{
		DWORD i;
		for (i = 0; i < cSubKeys; i++) 
		{ 
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey, 
				&cbName, 
				NULL, 
				NULL, 
				NULL, 
				&ftLastWriteTime); 
			if (retCode == ERROR_SUCCESS) 
			{
				LONG lRet;
				HKEY hKey1;
				TCHAR szKeyName[1000];
				HRESULT hr = StringCchPrintf(szKeyName,   // Open each of the subkeys under TAP_DEV_CLASS
					ARRAYSIZE(szKeyName),
					TEXT("%s%s"),
					TAP_DEV_CLASS,
					achKey);
				if (SUCCEEDED(hr))
				{
					lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE,szKeyName, 0L, KEY_READ, &hKey1);
					if (lRet == ERROR_SUCCESS)
					{
						DWORD dwType=REG_SZ;
						DWORD dwSize=MAX_KEY_LENGTH;
						TCHAR szValue[512];
						int lRet1;
						lRet1 = RegQueryValueEx(hKey1, TEXT("ComponentID"), NULL,
							&dwType, (LPBYTE)szValue, &dwSize);
						if (lRet1 == ERROR_SUCCESS)
						{
							TCHAR szTapDevName[] = TAP_DEV_NAME; 
							int equal = CompareString(LOCALE_SYSTEM_DEFAULT,
								NORM_IGNORECASE, szTapDevName, ARRAYSIZE(szTapDevName),
								szValue, ARRAYSIZE(szTapDevName));
							if (CSTR_EQUAL == equal) // Is this device's Name/ComponentID the TAP device TAP_DEV_NAME?
							{
								dwSize = MAX_KEY_LENGTH; // important; You should reinitialize
								// Get the TAP Device GUID.
								lRet1 = RegQueryValueEx(hKey1, TEXT("NetCfgInstanceId"), NULL,
									&dwType,(LPBYTE)szValue, &dwSize);
								if (lRet1 == ERROR_SUCCESS)
								{
									size_t strlength;
									HRESULT hr = StringCchLength(szValue, STRSAFE_MAX_CCH, &strlength);
									StringCchCopy(szGUID, strlength+1, szValue);
									bRet = true;
									break;
								}
							}
						}
					}
					RegCloseKey(hKey1);
				}
				else
				{
					break;
				}
			}
		}
	} 
	return bRet;
}

/* Get the Name of the device (eg. Local Area Connection 4). May be useful debugger/info printing */
void GetDeviceHumanName(TCHAR szGuid[], TCHAR szHumanName[])
{
	size_t strlength;
	StringCchLength(szGuid, STRSAFE_MAX_CCH, &strlength);
	if (strlength > 0)
	{
		int iCkLen = 1000;
		TCHAR szConnectionKey[1000] = TAP_DEV_CLASS;
		StringCchCat(szConnectionKey, iCkLen, TEXT("\\"));
		StringCchCat(szConnectionKey, iCkLen, szGuid);
		StringCchCat(szConnectionKey, iCkLen, TEXT("\\Connection") );
		HKEY hKey;
		int lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, szConnectionKey, 0L, KEY_READ, &hKey);
		if (lRet == ERROR_SUCCESS)
		{
			DWORD dwSize = 255;
			TCHAR szValue[255];
			DWORD dwType = REG_SZ;
			lRet = RegQueryValueEx(hKey, TEXT("Name"), NULL,  &dwType,(LPBYTE)szValue, &dwSize);
			if (lRet == ERROR_SUCCESS)
			{
				StringCchCopy(szHumanName, 255, szValue);
			}
		}
		RegCloseKey(hKey);
	}
}

/* Get the GUID of the TAP device */
bool GetDeviceGuid(__out TCHAR guid[])
{
	bool bRet = false;
	LONG lRet;
	HKEY hKey;
	lRet = RegOpenKeyEx (HKEY_LOCAL_MACHINE, TAP_DEV_CLASS, 0L, KEY_READ , &hKey);
	if(lRet == ERROR_SUCCESS)
	{
		if (SearchForDeviceGuid(hKey, guid))
		{
			bRet = true;
		}
	}
	RegCloseKey(hKey);
	return bRet;
}

static UINT TAP_CONTROL_CODE(UINT request, UINT method)
{
	return CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS);
}

/* Open the TAP interface in Overlapped I/O mode. Easily modified to open TUN interface */
HANDLE TunnelMgr::openTunInterface()
{
	HANDLE hDev = INVALID_HANDLE_VALUE;
	TCHAR devGuid[1000];
	if (GetDeviceGuid(devGuid))
	{
		// Open the device in TAP mode. See OS_tun_mgr.h for further details
		TCHAR UsermodeDeviceSpace[1000];
		StringCchPrintf(UsermodeDeviceSpace, 1000, TEXT("%s%s.tap"), TEXT("\\\\.\\Global\\"), devGuid);
		hDev = CreateFile(UsermodeDeviceSpace,
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_WRITE | FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING, 
			FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, // Note: Overlapped I/O
			NULL);

		if (hDev != INVALID_HANDLE_VALUE)
		{
			int status = 1; // init to "On"
			DWORD sizeReturned;

			/* Set the device to have "active media"/plugged-in status */
			if (!DeviceIoControl(hDev,
				TAP_CONTROL_CODE(TAP_IOCTL_SET_MEDIA_STATUS, METHOD_BUFFERED),
				&status,
				sizeof(status),
				&status,
				sizeof(status),
				&sizeReturned,
				NULL
				))
			{
				CloseHandle(hDev);
				hDev = INVALID_HANDLE_VALUE;
			}
		}
	}
	return hDev;
}



/* Equivalent of the *NIX select() loop in *NIX OS_listen() */
bool TunnelMgr::listen()
{
  /* Uses Microsoft overlapped I/O:
  http://msdn.microsoft.com/en-us/library/aa365683%28VS.85%29.aspx  */

  // Allocate Buffers for the IN and OUT read packets (read documentation for details).
  // IN read packet is handled by Listen FD. So IP_MAXPACKET is the read size.
  m_tInReadPkt.m_pData = (char*)malloc(LISTEN_READ_SIZE);
  assert(m_tInReadPkt.m_pData);
  memset(&wsaBuf, 0, sizeof(wsaBuf)); // WSARecv requires that the buffer be in the form requested here.
  wsaBuf.buf = m_tInReadPkt.m_pData;

  // OUT Read packet is handled by Tun FD. So ETHERNET_READ_SIZE is the read size
  m_tOutReadPkt.m_pData = (char*)malloc(ETHERNET_READ_SIZE);
  assert(m_tOutReadPkt.m_pData);

  struct sockaddr_in tInAddr;
  memset(&tInAddr, 0, sizeof(tInAddr));
  tInAddr.sin_family = AF_INET;
  tInAddr.sin_port = htons(m_iPort);
  tInAddr.sin_addr.s_addr = htonl(m_uListenIP);

  WSADATA wsaData;
  WSAPROTOCOL_INFO wsp = {0};
	GROUP g = {0};

  if (!m_bInit)
  {
    eprintf("win_tun_mgr: Unable to listen until initialized\n");
  }
  else if (WSAStartup(MAKEWORD(2,2), &wsaData) == NO_ERROR)
  {
    eprintf("win_tun_mgr: WSAStartup failed!\n");
  }
  // Open our connection for incoming packets - in Overlapped mode
  else if ((m_sListenFd = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, g, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET)
  {
    WSACleanup();
    eprintf("win_tun_mgr: Socket creation failed!\n");
  }
  // Open TUN/TAP interface in Overlapped I/O mode
  else if ((m_hTunFd = openTunInterface()) == INVALID_HANDLE_VALUE)
  {
    WSACleanup();
    eprintf("win_tun_mgr: Tun interface did not open\n");
  }
  else if (SOCKET_ERROR == bind(m_sListenFd, (SOCKADDR*)&tInAddr, sizeof(tInAddr)))
  {
    WSACleanup();
    eprintf("win_tun_mgr: Bind to well known port fail!\n");
  }
  // All initializations successful!
  else
  {
    int srcAddrSize = sizeof(srcAddr);
    // Equivalent of the Linux select loop
    if (!ReadFileEx(m_hTunFd,
      m_tOutReadPkt.m_pData,
      ETHERNET_READ_SIZE,
      &tunOverlapped,
      TapReadCallback))
    {
      eprintf("ReadFileEx failed! Tun manager probably wont work!\n");
    }
    else if (!WSARecvFrom(m_sListenFd,
      &wsaBuf,
      LISTEN_READ_SIZE,
      NULL,
      0,
      (SOCKADDR*)&srcAddr,
      &srcAddrSize,
      (LPWSAOVERLAPPED)&listenOverlapped, // OVERLAPPED and WSAOVERLAPPED are compatible
      ListenFdReadCallback))
    {
      eprintf("WsaRecvFrom failed. Tun manager wont work!\n");
    }
    else
    {
      while(1)
      {
        // TODO: Improve this by using other methods. SleepEx is not efficient.
        SleepEx(INFINITE, TRUE);
      }
    }
  }
  WSACleanup();
  return true;
}



// Read a Ethernet frame from the TunTap device
// As with the Linux code (Eric's code), assumed that Ethernet frame is read in 1 call to ReadFileEx()!
VOID WINAPI TunnelMgr::tapReadCompletedRoutine(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap)
{
  // Part 1. Read Frame from TAP device
  bool bPart1Success = false;
  bool bReentrantRead = false;
  if (0 != m_tOutReadPkt.m_uOffset) // If this is the first time the packet was read
  {
    bReentrantRead = true;
    m_tOutReadPkt.m_bComplete = false; // false always

    if (0 != dwErr) // error
    {
      dprintf("Did not read TAP frame");
      delete[] m_tOutReadPkt.m_pData;
    }
    else
    {
      // TODO: call GetOverlappedResult and call GetLastError
      DWORD dwBytesRead;
      if (GetOverlappedResult(m_hTunFd, lpOverLap, &dwBytesRead, FALSE))
      {
        DWORD dwOtherError = GetLastError(); // Make sure there was no other error
        if (ERROR_SUCCESS == dwOtherError)   // success :-/
        {
          m_tOutReadPkt.m_uOffset   += cbBytesRead;
          m_tOutReadPkt.m_uSize      = cbBytesRead;
          m_tOutReadPkt.m_bComplete  = true;

          bPart1Success = true;
          if (!handleFrame(m_tOutReadPkt))
          {
            eprintf("Unable to handle new frame.\n");
            bPart1Success = false;
          }
        }
        else
        {
          dprintf("Other error with read : %d\n", dwOtherError);
        }
      }
    }

    // Part 2. Write the frame to the Listen FD
    // We have read the frame successfully and made it an IP packet via handleFrame. So now send it on ListenFD!
    if (bPart1Success && m_tOutReadPkt.m_bComplete)
    {
      while (NULL != m_tOutReadPkt.m_pData)
      {
        // Attempt to send packet till fwdOut fails
        if (!fwdOut(m_tOutReadPkt))
        {
          eprintf("Unable to fwdOut()\n");
          break;
        }
      }
    }
    else
    { 
      eprintf("win_tun_mgr: part 1 failed. Not forwarding out!\n");
    }

    // Clear up the packet after attempted reads and/or sends.
    destroyPkt(m_tOutReadPkt);
    memset(&tunOverlapped, 0, sizeof(tunOverlapped));  // important to set to 0
    memset(&m_tOutReadPkt, 0, sizeof(m_tOutReadPkt));

    // Call the next ReadFileEx.
    m_tOutReadPkt.m_pData = new char[ETHERNET_READ_SIZE];
    TunnelMgr &tmInstance = TunnelMgr::getInstance();
    ReadFileEx(m_hTunFd,
      m_tOutReadPkt.m_pData,
      ETHERNET_READ_SIZE,
      &tunOverlapped,
      TapReadCallback);
  }
}

VOID WINAPI TunnelMgr::listenReadCompletedRoutine(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap)
{
  bool bReentrantRead = false;
  bool bSuccess       = false;

  if (ERROR_SUCCESS != dwErr)
  {
    struct ip *pIpHdr = (struct ip*) m_tInReadPkt.m_pData; // buffer passed to this callback
    

    // If offset is 0, this is the first time we are reading data
    if (0 == m_tInReadPkt.m_uOffset)
    {
      // Get at least the IP header 
      if (cbBytesRead >= (int)sizeof(struct ip))
      {
        //TODO: IP/Port
        m_tInReadPkt.m_uIP = ntohl(srcAddr.sin_addr.s_addr);
        m_tInReadPkt.m_uPort = ntohs(srcAddr.sin_port);

        m_tInReadPkt.m_uOffset = cbBytesRead;
        m_tInReadPkt.m_uSize   = ntohs(pIpHdr->ip_len);
        dprintf("readpkt offset:%u\n", (unsigned int)m_tInReadPkt.m_uOffset);
        dprintf("readpkt size:%u\n", (unsigned int)m_tInReadPkt.m_uSize);
        {
          char szIP[16];
          net_itoa(m_tInReadPkt.m_uIP, szIP);
          dprintf("readpkt IP:%s Port:%u\n", szIP, m_tInReadPkt.m_uPort);		
        }

        // Did we get the whole packet
        if (cbBytesRead >= pIpHdr->ip_len)
        {
          bSuccess = true;
          m_tInReadPkt.m_bComplete = true;
          if (4 != pIpHdr->ip_v)
          {
            eprintf("Version of header is not 4 is '%d', dropping.\n", pIpHdr->ip_v);
            bSuccess = false;
          }
        }
        // We didn't get the whole packet. So issue a read call :-/
        else
        {
          int srcAddrSize = sizeof(srcAddr);
          if (!WSARecvFrom(m_sListenFd,
            &wsaBuf,
            LISTEN_READ_SIZE,
            NULL,
            0,
            (SOCKADDR*)&srcAddr,
            &srcAddrSize,
            (LPWSAOVERLAPPED)&listenOverlapped,
            ListenFdReadCallback))
          {
            dprintf("WSARecvFrom failed with error code %d. Tun manager might not work\n", GetLastError());
            bSuccess = false;
          }
          else
          {
            bSuccess = true;
          }
        }
      }
      else
      {
        bSuccess = false;
      }
    }
    // Something was screwed up last read. Check it out
    else
    {
      m_tInReadPkt.m_uOffset += cbBytesRead;
      if (m_tInReadPkt.m_uOffset >= m_tInReadPkt.m_uSize)
      {
        m_tInReadPkt.m_bComplete = true;
      }
    }

    /*
     * Try handling and sending the packet to the TUN device
     * Packet read completed. Now convert to frame and send to TAP device
     */
    if (m_tInReadPkt.m_bComplete && bSuccess)
    {
      // Replace the IP and set it up with a local IP address on the TUN device
      if (!replaceIp(m_tInReadPkt))
      {
        eprintf("Packet replaceip failed!\n");
        bSuccess = false;
      }
      // Convert to frame to send on TAP device
      else if (!convertToFrame(m_tInReadPkt))
      {
        eprintf("Packet conversion to frame failed!\n");
        bSuccess = false;
      }
      // TAP device packet set up. Now send it
      int writtenSoFar = 0;
      while(1)
      {
        DWORD dwWritten;
        OVERLAPPED stOverlapped;
        memset(&stOverlapped, 0, sizeof(stOverlapped));
        if (WriteFile(m_hTunFd, m_tInReadPkt.m_pData, m_tInReadPkt.m_uSize, &dwWritten, &stOverlapped))
        {
          writtenSoFar += dwWritten;
          if (writtenSoFar == m_tInReadPkt.m_uSize)
          {
            break;
          }
        }
        else
        {
          dprintf("Error with sending data to TUN device %d\n", GetLastError());
          bSuccess = false;
          break;
        }
      }
    }

    // Deleted if read was completed, or we failed altogether
    if (m_tInReadPkt.m_bComplete || !bSuccess)
    {
      // Do we need to destroy the packet?
      //destroyPkt(m_tInReadPkt);
      memset(&m_tInReadPkt, 0, sizeof(m_tInReadPkt));
    }
  }
  else
  {
    dprintf("listenReadCompleteRoutine: error %d\n", dwErr);
  }
  memset(&srcAddr, 0, sizeof(srcAddr));
}

// OVERLAPPED_COMPLETION_ROUTINE
VOID WINAPI TapReadCallback(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap)
{
  TunnelMgr &tmInstance = TunnelMgr::getInstance();
  tmInstance.tapReadCompletedRoutine(dwErr, cbBytesRead, lpOverLap);
}

// WSAOVERLAPPED_COMPLETION_ROUTINE
VOID WINAPI ListenFdReadCallback(DWORD dwErr, DWORD cbBytesRead, LPWSAOVERLAPPED lpOverLap, DWORD dwFlags)
{
  TunnelMgr &tmInstance = TunnelMgr::getInstance();
  tmInstance.listenReadCompletedRoutine(dwErr, cbBytesRead, lpOverLap);
}


#endif /* _MSC_VER */