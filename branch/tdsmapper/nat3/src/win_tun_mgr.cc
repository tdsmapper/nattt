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
#include <errno.h>


#include "OS_tun_mgr.h"
#include "types.h"
#include "tun_mgr.h"
#include "tun_defs.h"
#include "tun_in_ent.h"
#include "tun_out_ent.h"
#include "functions.h"

OVERLAPPED tunOverlapped;
WSAOVERLAPPED listenOverlapped;
int srcAddrSize;
struct sockaddr_in srcAddr;
WSABUF wsaBuf;
DWORD dwFlags;

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
                  eprintf("The dev GUID is %s\n", szGUID);
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
bool GetDeviceHumanName(TCHAR szGuid[], TCHAR szHumanName[])
{
  bool bRet = false;
	size_t strlength;
	StringCchLength(szGuid, STRSAFE_MAX_CCH, &strlength);
	if (strlength > 0)
	{
		int iCkLen = 1000;
		TCHAR szConnectionKey[1000] = TAP_DEV_NETWORK;
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
        eprintf("The device name is %s\n", szHumanName);
        bRet = true;
			}
		}
		RegCloseKey(hKey);
	}
  return bRet;
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

			/* Set the device to have "active media"/plugged-in status in just TAP mode (default) */
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
//IP Address on ArunMadh's machine: 00:ff:1c:87:46:80
bool TunnelMgr::configTunInterface(char *p_szDevice)  // p_szDevice is not needed!
{
  bool bRet = false;

  // Returns the MAC address of the TAP device
  unsigned long nLen = 0;

	// Get MAC address of the TAP device
  if (!DeviceIoControl(m_hTunFd, 
    TAP_IOCTL_GET_MAC, 
    m_pTapMac, 
    sizeof(m_pTapMac), 
    m_pTapMac, 
    sizeof(m_pTapMac), 
    &nLen, 
    0))
  {
    fprintf(stderr, "Error %d: Unable to get the MAC address of the TAP device."
      " Please contact the developer if this problem persists\n", GetLastError());
  }

  // Get the MTU of the TAP device
  else if (!DeviceIoControl(m_hTunFd, 
      TAP_IOCTL_GET_MTU, 
      &m_iTunMTU, 
      sizeof(m_iTunMTU), 
      &m_iTunMTU, 
      sizeof(m_iTunMTU), 
      &nLen, 
      NULL)) 
  {
    fprintf(stderr, "Error %d: Unable to get the MTU for the TAP device. "
      "Please contact the developers if this error persists. \n", GetLastError());
	}

  // Set the IP address. Defering setting up routing tables. Does not seem to be needed on Windows
  else
  {
    TCHAR szDevGUID[256];
    char szDevName[256];

    char szNetshCall[256];
    char szNetAddr[256];
    char szNetmask[256];

    // Local network address + 1 = adapter address
    net_itoa(m_uLocalNet + 1, szNetAddr);
    net_itoa(m_uMask, szNetmask);

    if (GetDeviceGuid(szDevGUID))
    {
      if (GetDeviceHumanName(szDevGUID, szDevName))
      {
        snprintf(szNetshCall, sizeof(szNetshCall), 
          "netsh interface ip set address \"%s\" static %s %s", szDevName,
          szNetAddr, szNetmask);
        eprintf("Netsh call is %s\n", szNetshCall);
        int iRet = system(szNetshCall);
        DWORD dwLastError = GetLastError();
        if (0 == iRet)
        {
          if (ENOENT == dwLastError)
          {
            fprintf(stderr, "Error %d: netsh interface call failed!\n", dwLastError);
          }
          else
          {
            bRet = true;
          }
        }
        else if (-1 == iRet)
        {
          fprintf(stderr, "Error %d: netsh interface call failed!\n", GetLastError());
        }
        else
        {
          bRet = true;
        }
      }
    }
  }
  return bRet;
}



/* Equivalent of the *NIX select() loop (TunnelMgr::listen) */
bool TunnelMgr::listen()
{
  /* Uses Microsoft overlapped I/O:
  http://msdn.microsoft.com/en-us/library/aa365683%28VS.85%29.aspx  */
  WSAPROTOCOL_INFO wsp = {0};
	GROUP g = {0};

  /* This will cause GEN_DEV_FAILURE if not initalized */
  memset(&tunOverlapped,    0, sizeof(tunOverlapped));  // important to set to 0
  memset(&listenOverlapped, 0, sizeof(listenOverlapped));  // important to set to 0

  struct sockaddr_in tInAddr;
  memset(&tInAddr, 0, sizeof(tInAddr));
  tInAddr.sin_family = AF_INET;
  tInAddr.sin_port = htons(m_iPort);
  tInAddr.sin_addr.s_addr = htonl(m_uListenIP);

  if (!m_bInit)
  {
    eprintf("win_tun_mgr: Unable to listen until initialized\n");
  }
  // Open our connection for incoming packets - in Overlapped mode
  else if ((m_sListenFd = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, g, WSA_FLAG_OVERLAPPED)) == INVALID_SOCKET)
  {
    eprintf("win_tun_mgr: Socket creation failed!\n");
  }
  // Open TUN/TAP interface in Overlapped I/O mode
  else if ((m_hTunFd = openTunInterface()) == INVALID_HANDLE_VALUE)
  {
    eprintf("win_tun_mgr: Tun interface did not open\n");
  }
  else if (SOCKET_ERROR == bind(m_sListenFd, (SOCKADDR*)&tInAddr, sizeof(tInAddr)))
  {
    eprintf("win_tun_mgr: Bind to well known port fail with %d!. "
      "Please make sure the address in the config file is correct, and that the port is usable\n", GetLastError());
  }
  else if(configTunInterface(NULL))
  {
    eprintf("win_tun_mgr: Unable to configure tun interface!\n");
  }
  // All initializations successful!
  else
  {
    // Allocate Buffers for the IN and OUT read packets (read documentation for details).
    // IN read packet is handled by Listen FD. So IP_MAXPACKET is the read size.
    clearPkt(m_tInReadPkt);
    m_tInReadPkt.m_pData = new char[LISTEN_READ_SIZE];
    //memset(&wsaBuf, 0, sizeof(wsaBuf)); // WSARecv requires that the buffer be in the form requested here.

    // OUT Read packet is handled by Tun FD. So ETHERNET_READ_SIZE is the read size
    clearPkt(m_tOutReadPkt);
    m_tOutReadPkt.m_pData = new char[ETHERNET_READ_SIZE];
    memset(m_tOutReadPkt.m_pData, 0, ETHERNET_READ_SIZE);
    
    memset (&srcAddr, 0, sizeof(srcAddr));
    srcAddrSize        = sizeof(srcAddr); // Cannot be allocated on the stack frame. Needs to be accessible always
    int tapReadSize    = ETHERNET_READ_SIZE;

    wsaBuf.buf = m_tInReadPkt.m_pData;
    wsaBuf.len = LISTEN_READ_SIZE;
    dwFlags = 0;
    DWORD dwBytesRead = 0;
    //listenOverlapped.hEvent = WSACreateEvent();
    int err = GetLastError();
    eprintf("Last error is %d\n", err);
    // Equivalent of the *NIX select loop
    if (!ReadFileEx(m_hTunFd,
      m_tOutReadPkt.m_pData,
      tapReadSize,
      &tunOverlapped,
      TapReadCallback))
    {
      eprintf("ReadFileEx failed with %d! Tun manager probably wont work!\n", GetLastError());
      abort();
    }
    // Note that the return value of WSARecvFrom is actually 0 for no error
    else if ((WSARecvFrom(m_sListenFd,   // Socket
      &wsaBuf,                    // Buffer
      1,                          // Number of buffers
      &dwBytesRead,                       // Number of bytes received irrelevant since Overlapped I/O
      &dwFlags,                   // Flags
      (SOCKADDR*)&srcAddr,        // Source address
      &srcAddrSize,               // size of the src addr structure
      &listenOverlapped, // OVERLAPPED structure and WSAOVERLAPPED are compatible
      ListenFdReadCallback) != 0) && (WSAGetLastError() != ERROR_IO_PENDING))      // Callback
    {
      eprintf("WsaRecvFrom failed with %d! Tun manager wont work!\n", WSAGetLastError());
      abort();
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
  return true;
}



// Read a Ethernet frame from the TunTap device
// As with the Linux code (Eric's code), assumed that Ethernet frame is read in 1 call to ReadFileEx()!
VOID WINAPI TunnelMgr::tapReadCompletedRoutine(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap)
{
  assert (cbBytesRead <= ETHERNET_READ_SIZE);
  // Part 1. Read Frame from TAP device
  //if (0)
  {
    eprintf("Grabbed a frame of size %d for %x.%x.%x.%x.%x.%x\n",
      cbBytesRead, m_tOutReadPkt.m_pData[0], m_tOutReadPkt.m_pData[1], m_tOutReadPkt.m_pData[2],
      m_tOutReadPkt.m_pData[3], m_tOutReadPkt.m_pData[4], m_tOutReadPkt.m_pData[5]);
  }
  bool bPart1Success = false;
  m_tOutReadPkt.m_bComplete = false; // false always

  if (0 != dwErr) // error
  {
    eprintf("Did not read TAP frame");
    abort();
  }
  else
  {
    // TODO: call GetOverlappedResult and call GetLastError
    //DWORD dwBytesRead;
    //if (!GetOverlappedResult(m_hTunFd, lpOverLap, &dwBytesRead, TRUE))
    //{
    //  DWORD dwOtherError = GetLastError(); // Make sure there was no other error
    //  if (ERROR_SUCCESS == dwOtherError)   // success :-/
    //  {
        m_tOutReadPkt.m_uOffset   += cbBytesRead;
        m_tOutReadPkt.m_uSize      = cbBytesRead;
        m_tOutReadPkt.m_bComplete  = true;

        bPart1Success = true;
        if (!handleFrame(m_tOutReadPkt))
        {
          //eprintf("Unable to handle new frame.\n"); // COMM
          bPart1Success = false;
        }
      /*}
      else
      {
        eprintf("Other error with read : %d\n", dwOtherError);
      }
    }*/
  }

  // Part 2. Write the frame to the Listen FD
  // We have read the frame successfully and made it an IP packet via handleFrame. So now send it on ListenFD!
  if (bPart1Success)
  {
    while (NULL != m_tOutReadPkt.m_pData)
    {
      // Attempt to send packet till fwdOut fails
      if (!fwdOut(m_tOutReadPkt))
      {
        // Packet will always be destroyed when fwdOut ends - either failure or success.
        //eprintf("Unable to fwdOut()\n");
        break;
      } 
    }
  }
  else
  { 
    //eprintf("win_tun_mgr: part 1 failed. Not forwarding out!\n");
  }

  //assert (m_tOutReadPkt.m_pData != NULL); // Packet should have been destroyed //TODO/XXX
  memset(&tunOverlapped, 0, sizeof(tunOverlapped));  // important to set to 0
  m_tOutReadPkt.m_pData = new char[ETHERNET_READ_SIZE];
  assert (m_tOutReadPkt.m_pData);

  // Call the next ReadFileEx.
  if (!ReadFileEx(m_hTunFd,
    m_tOutReadPkt.m_pData,
    ETHERNET_READ_SIZE,
    &tunOverlapped,
    TapReadCallback))
  {
    eprintf("ReadFileEx() failed with %d. Aborting.\n", GetLastError());
    abort();
  }
}

// Re-entrant style packet reading
VOID WINAPI TunnelMgr::listenReadCompletedRoutine(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap)
{
  bool bReentrantRead = false;
  bool bSuccess       = false;

  if (ERROR_SUCCESS == dwErr)
  {
    struct ip *pIpHdr = (struct ip*) m_tInReadPkt.m_pData; // buffer passed to this callback

    // If offset is 0, this is the first time we are reading data
    if (0 == m_tInReadPkt.m_uOffset)
    {
      // Did we get at least the IP header?
      // Since this is the first read, its enough to just check the num bytes read
      if (cbBytesRead >= (int)sizeof(struct ip))
      {
        m_tInReadPkt.m_uIP = ntohl(srcAddr.sin_addr.s_addr);
        m_tInReadPkt.m_uPort = ntohs(srcAddr.sin_port);
        {
          char szIP[16];
          net_itoa(m_tInReadPkt.m_uIP, szIP);
          eprintf("readpkt IP:%s Port:%u\n", szIP, m_tInReadPkt.m_uPort);		
        }

        m_tInReadPkt.m_uOffset = cbBytesRead;
        m_tInReadPkt.m_uSize   = ntohs(pIpHdr->ip_len);
        {
          eprintf("readpkt offset:%u\n", (unsigned int)m_tInReadPkt.m_uOffset);
          eprintf("readpkt size:%u\n",   (unsigned int)m_tInReadPkt.m_uSize);
        }
  
        // Did we get the whole packet
        if (cbBytesRead >= ntohs(pIpHdr->ip_len))
        {
          bSuccess = true;
          m_tInReadPkt.m_bComplete = true;
          if (4 != pIpHdr->ip_v)
          {
            eprintf("Version of header is not 4 is '%d', dropping.\n", pIpHdr->ip_v);
            bSuccess = false;
          }
        }
      }
      else
      {
        bSuccess = false;
      }
    }
    // We got a partial packet. This is the rest of the packet
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
    // Successful and complete read
    if (bSuccess && m_tInReadPkt.m_bComplete)
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
      else
      {
        m_tInReadPkt.m_uSize = m_tInReadPkt.m_uOffset; // TODO
        // TAP device packet set up. Now send it
        int writtenSoFar = 0;
        while(1)
        {
          if (!writePkt(m_hTunFd, m_tInReadPkt, true))
          {
            bSuccess = false;
            break;
          }
          else
          {
            if (0 == m_tInReadPkt.m_uOffset)
            {
              bSuccess = true;
              break;
            }
          }
        }
      }
    }
  }
  // Some error; drop the packet
  else
  {
    eprintf("listenReadCompleteRoutine: error %d/%d\n", dwErr, GetLastError());
  }

  // Full packet not received, and (partial) read was successful:  Read whatever remains
  if (!m_tInReadPkt.m_bComplete && bSuccess)
  {
    wsaBuf.len = m_tInReadPkt.m_uSize - m_tInReadPkt.m_uOffset; // amount to read
    wsaBuf.buf = &m_tInReadPkt.m_pData[m_tInReadPkt.m_uOffset];
  }
  // Full packet received AND/OR Failed receive/forward: Destroy all evidence and re-create
  else
  {
    destroyPkt(m_tInReadPkt);
    wsaBuf.len           = LISTEN_READ_SIZE;  // amount to read is passed in this structure
    m_tInReadPkt.m_pData = new char[LISTEN_READ_SIZE];
    wsaBuf.buf           = m_tInReadPkt.m_pData;
  }
  memset(&srcAddr, 0, sizeof(srcAddr));
  memset(&listenOverlapped, 0, sizeof(listenOverlapped));

  srcAddrSize = sizeof(srcAddr);
  dwFlags = 0;
  if (WSARecvFrom(m_sListenFd,   // Socket
      &wsaBuf,                    // Buffer
      1,                          // Number of buffers
      NULL,                       // Number of bytes received irrelevant since Overlapped I/O
      &dwFlags,                   // Flags
      (SOCKADDR*)&srcAddr,        // Source address
      &srcAddrSize,               // size of the src addr structure
      (LPWSAOVERLAPPED)&listenOverlapped, // OVERLAPPED structure and WSAOVERLAPPED are compatible
      ListenFdReadCallback))      // Callback
  {
    if (WSAGetLastError() != ERROR_IO_PENDING)
    {
      eprintf("WSARecvFrom failed with %d\n", GetLastError());
      abort();
    }
  }
}

// OVERLAPPED_COMPLETION_ROUTINE
VOID WINAPI TapReadCallback(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap)
{
  dprintf("tap Called!!\n");
  TunnelMgr &tmInstance = TunnelMgr::getInstance();
  tmInstance.tapReadCompletedRoutine(dwErr, cbBytesRead, lpOverLap);
}

// WSAOVERLAPPED_COMPLETION_ROUTINE
VOID WINAPI ListenFdReadCallback(DWORD dwErr, DWORD cbBytesRead, LPWSAOVERLAPPED lpOverLap, DWORD dwFlags)
{
  dprintf("listen Called!!\n");
  TunnelMgr &tmInstance = TunnelMgr::getInstance();
  tmInstance.listenReadCompletedRoutine(dwErr, cbBytesRead, lpOverLap);
}


#endif /* _MSC_VER */