package ntd.scala.exercises.std

object Regex {
  object Opsview {
    private val IP_BYPASS = """(?:-(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))?"""
    private val GROUP_BRAS_ID = """([A-Z]{3}-MP-(?:\d{2}|Backup)-\d{2})"""
    private val GROUP_SWITCH = """(.*(?:DF24|DS24|HS24|HS48|HS57|HS67|HS68|HW12|HW24|HW28|HW48|HW50|HW57|HW58|HW67|HW68|HW93|GS32|ME35|MG37|GS31|GS30)).*"""
    private val GROUP_HOST = """(.*(?:GC08|GC16|GC56|GC57|ES55|ES52|ES12|ES50|ES60|AL42))"""
    private val GROUP_LOCAL = """(?:NOC-NET-)(.*?(?:ClearDDOS|Local|DR|FrontEnd|DMZ|ISC|CSOC|DNS|HAN|Storage|SPINE|Fshare|SPAN|PayTV|FPTPLAY|FPlay|VOD)(?:[A-Za-z0-9-]{2,})?)(?:-\d{2,3}\.)"""
    // \[(\d+)\] (?:SERVICE|HOST) ALERT: (?:NOC-NET-)(.*?(?:ClearDDOS|Local|DR|FrontEnd|DMZ|ISC|CSOC|DNS|HAN|Storage|SPINE|Fshare|SPAN|(?:.*)PayTV|(?:.*)FPTPLAY|(?:.*)FPlay|(?:.*)VOD)(?:[A-Za-z0-9-]{2,})?)-\d{2,3}\..*

    // 2018-10-26
    private val GROUP_PE = """([A-Z]{3}-PE-\d{2}-\d{2})"""
    private val GROUP_MC_SMC = """([A-Z]{3}-(?:SMC|MC)-\d{2})"""
    private val GROUP_GW = """([A-Z]{3}-(?:.*GW|.*SW|NIX|HUB|ACX|.*Trigger|QFX)(?:[A-Za-z0-9-]{2,}))"""
    private val GROUP_CGNAT = """([A-Z]{2,3}-CGNAT-\d{2})"""
    private val GROUP_POWER = """([A-Z0-9]+PW[A-Z0-9]+)"""
    private val GROUP_OTS = """([A-Z]{3}\.[A-Z]{3}\.\d+)"""

    private val GROUP_UPE = """MPLS(-[A-Z0-9]+)?-([A-Z0-9]+)-\d{2}"""
    private val GROUP_NPE = """(.*-)?([A-Z0-9]+NPE[A-Z0-9]+)"""
    private val GROUP_IPMS = """(?:.*-)?([A-Za-z0-9\.]+)(?:-|_)IPMS(?:.*)?-\d{2,3}"""
    private val GROUP_OPMS = """(?:.*-)?([A-Za-z0-9\.]+)(?:-|_)OPMS(?:.*)?-\d{2,3}"""
    private val GROUP_RR = """(?:NOC-NET-)?([A-Z]{2,3}-(?:RR|VRR)-\d{2})"""
    private val GROUP_OOB = """(?:NOC-NET-)?([A-Z]{2,3}-OOB-\d{2})"""
    private val GROUP_FW = """(?:NOC-NET-)?(.*?FW(?:[A-Za-z0-9-]{2,})?)(?:-\d{2,3}\.)"""
    private val GROUP_CACHE = """(?:NOC-NET-)?(.*Cache((-[A-Z]+-\d{2})|(-\d{3}\.\d{3}))?)-?"""
    private val GROUP_IVOICE = """(?:NOC-NET-)?(.*iVoice(?:GW)?(?:(?:-[A-Z0-9]+-\d{2})|(?:-.{2,4})))-\d{3}"""
    private val GROUP_HOSTING = """(?:NOC-NET-)?(.*Hosting(?:-[A-Za-z0-9-]{2,}))-\d{3}"""
    private val GROUP_RP = """(?:NOC-NET-)?(.*-RP(?:-[A-Za-z0-9-]{2,}))-\d{3}"""

    val REGEX_BRAS_ID = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: (?:NOC-NET-)?${GROUP_BRAS_ID}.*""".r
    val REGEX_SWITCH = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: (?:.*\\-)*${GROUP_SWITCH}.*""".r
    val REGEX_HOST = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: .*-${GROUP_HOST}-.*""".r

    val REGEX_PE = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: (?:NOC-NET-)?${GROUP_PE}.*""".r
    val REGEX_MC_SMC = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: (?:NOC-NET-)?${GROUP_MC_SMC}.*""".r
    val REGEX_GW = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: (?:NOC-NET-)?${GROUP_GW}${IP_BYPASS}""".r
    val REGEX_CGNAT = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: (?:NOC-NET-)?${GROUP_CGNAT}.*""".r
    val REGEX_POWER = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: .*-${GROUP_POWER}.*""".r
    val REGEX_OTS = s"""\\[(\\d+)\\] (?:SERVICE) ALERT: ${GROUP_OTS}.*""".r

    val REGEX_UPE = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: .*-${GROUP_UPE}.*""".r
    val REGEX_NPE = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: ${GROUP_NPE}.*""".r
    val REGEX_IPMS = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: ${GROUP_IPMS}.*""".r
    val REGEX_OPMS = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: ${GROUP_OPMS}.*""".r
    val REGEX_RR = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: ${GROUP_RR}.*""".r
    val REGEX_OOB = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: ${GROUP_OOB}.*""".r
    val REGEX_Kibana = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: (Kibana)(-[A-Z]+)?.*""".r
    val REGEX_CACHE = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: ${GROUP_CACHE}.*""".r
    val REGEX_IVOICE = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: ${GROUP_IVOICE}.*""".r
    val REGEX_HOSTING = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: ${GROUP_HOSTING}.*""".r
    val REGEX_RP = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: ${GROUP_RP}.*""".r
    val REGEX_LOCAL = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: ${GROUP_LOCAL}.*""".r
    val REGEX_FW = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: ${GROUP_FW}.*""".r
    val REGEX_DDOS = s"""\\[(\\d+)\\] (?:SERVICE|HOST) ALERT: (Check-DDoS-Abor).*""".r
  }
  object Inf {
    private val HOST = """([A-Z]{4}\d{5}[A-Z]{2}\d{2})"""
    private val MODULE_1 = """(0\/\d+)"""
    private val MODULE_2 = """(\d+)"""
    private val MODULE_3 = """(\d{1}\/\d{1}\/\d{1,3})"""
    private val NUMBER = """([0-9]+)"""
    private val IP = """(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""
    // using for old OLT: GC57
    val REGEX_USER_PORT_DOWN = s""".*${HOST}: %DEVICE-3-LINKUPDOWN: p${MODULE_1} LinkDown.""".r
    val REGEX_USER_PORT_UP = s""".*${HOST}: %DEVICE-3-LINKUPDOWN: p${MODULE_1} LinkUp.""".r

    // using for new OLT: GC08, GC16
    val REGEX_USER_PORT_DOWN_V2 = s""".*${HOST}: %DEVICE-3-LINKUPDOWN: g${MODULE_1} LinkDown.""".r
    val REGEX_USER_PORT_UP_V2 = s""".*${HOST}: %DEVICE-3-LINKUPDOWN: g${MODULE_1} LinkUp.""".r

    val REGEX_INF_PORT_DOWN = s""".*${HOST}: %DEVICE-3-LINKUPDOWN: e${MODULE_1} LinkDown.""".r
    val REGEX_INF_PORT_UP = s""".*${HOST}: %DEVICE-3-LINKUPDOWN: e${MODULE_1} LinkUp.""".r

    /*val userPortDownP = s""".*${HOST}: %DEVICE-3-LINKUPDOWN: p${MODULE_1} LinkDown.""".r
    val userPortUpP = s""".*${HOST}: %DEVICE-3-LINKUPDOWN: p${MODULE_1} LinkUp.""".r
    val infPortDownP = s""".*${HOST}: %DEVICE-3-LINKUPDOWN: e${MODULE_1} LinkDown.""".r
    val infPortUpP = s""".*${HOST}: %DEVICE-3-LINKUPDOWN: e${MODULE_1} LinkUp.""".r*/

    val REGEX_HIGH_CPU = s""".*${HOST}: %OAM-5-CPU_BUSY: cpu is busy.""".r
    val REGEX_POWER_ERROR = s""".*${HOST}: %DEVICE-5-POWER-MANAGE: Power running no good detected, power NO : ${MODULE_2}.""".r
    val REGEX_REBOOT = s""".*${HOST}: %OAM-5-RELOAD_SUCCESSFULLY: reboot device successfully""".r
    val REGEX_CPE_ERROR = s""".* ${HOST}: .* ont ${MODULE_3}.* deregister reason sf""".r
    val REGEX_LOFI = s""".* ${HOST}: .* ont ${MODULE_3}.* deregister reason lofi""".r
    val REGEX_POWER_OFF = s""".* ${HOST}: .* ont ${MODULE_3}.* power off""".r
    val REGEX_LOS = s""".* ${HOST}: .* ont ${MODULE_3}.* deregister reason los""".r
    val REGEX_REGISTER = s""".* ${HOST}: .* ont ${MODULE_3}.* register successful""".r
    val REGEX_NEW_OLT = s""".*\\"${IP}.*1.3.6.1.4.1.13464.1.14.2.4.1.1.1.12.0.${NUMBER}.${NUMBER}], @value=.*\"${NUMBER}.*""".r
    /*val highCpuP = s""".*${HOST}: %OAM-5-CPU_BUSY: cpu is busy.""".r
    val powerErrorP = s""".*${HOST}: %DEVICE-5-POWER-MANAGE: Power running no good detected, power NO : ${MODULE_2}.""".r
    val rebootP = s""".*${HOST}: %OAM-5-RELOAD_SUCCESSFULLY: reboot device successfully""".r
    val cpeErrorP = s""".* ${HOST}: .* ont ${MODULE_3}.* deregister reason sf""".r
    val lofiP = s""".* ${HOST}: .* ont ${MODULE_3}.* deregister reason lofi""".r
    val powerOffP = s""".* ${HOST}: .* ont ${MODULE_3}.* power off""".r
    val losP = s""".* ${HOST}: .* ont ${MODULE_3}.* deregister reason los""".r
    val registerP = s""".* ${HOST}: .* ont ${MODULE_3}.* register successful""".r*/
  }
  object Kibana{
    private val PE_CITY ="""(HCM|HNI)"""
    private val GROUP_MC_SMC = """([A-Z]{3}-(?:SMC|MC)-\d{2})"""
    private val GROUP_GW = """([A-Z]{3}-(?:.*GW|.*SW|NIX|PE)(?:-\d{2}|-EPZ|-CG)+)"""
    private val GROUP_CGNAT = """([A-Z]{2,3}-CGNAT-\d{2})"""

    val DEVICE_ID = """([A-Z]{3}-[A-Z]+-[A-Z0-9]+-?[0-9]*?)"""
    val REGEX_PE =  s"""$PE_CITY-PE-\\d{2}-\\d{2}""".r
    val REGEX_SMC_MC = s"""$GROUP_MC_SMC""".r
    val REGEX_CGNAT = s"""$GROUP_CGNAT""".r
    val REGEX_BRAS = s"""[A-Z]{3}-MP-\\d{2}-\\d{2}""".r
    val REGEX_GW = s"""$GROUP_GW""".r
  }
  object OpsviewDeviceMapper extends Serializable {
    val GW = Seq("HKG", "SGP")
  }

  def main(args: Array[String]): Unit = {
    val log = Seq(
      "[1558371878] SERVICE ALERT: NOC-NET-HKG-PE-02-01-210.245.31.199;Interface NOC: 3052;CRITICAL;HARD;1;CRITICAL-PORT DOWN: xe-1/3/1#L3#HK-HCM#HCM-MC01-xe-7/2/1-U1_CAO-021615-434, throughput (in/out) 738.72/1818.82 Mbps, speed 9953",
      "[1558426247] SERVICE ALERT: NOC-NET-SGP-AggSW-02-01-210.245.31.217;BGP Peer Juniper;CRITICAL;SOFT;2;CRITICAL: Peer 42.112.4.15 / AS18403 has state active (0:02:19)",
      // HOST ALERT
      "[1558745665] HOST ALERT: INF-TNN-TNNP06701PWEN1U-25.163.20.2;DOWN;HARD;2;CRITICAL - 25.163.20.2: rta nan, lost 100%",
      "[1560212978] HOST ALERT: BTHT1-HCMP56706GC16-11.53.123.51;UP;HARD;2;OK - 11.53.123.51: rta 1.720ms, lost 0%",
      "[1556717946] SERVICE ALERT: INF-HPG-HPGP06106GC16-20.101.12.6;check_fts_port_pon_status_new: 7;WARNING;SOFT;1;PON PORT 7- KHONG CO MODULE PON",
      // Switch
      "[1560217784] SERVICE ALERT: INF-BDG-BDGP01701GC57-11.61.122.41;check_olt_power;WARNING;SOFT;1;(null)",
      "[1549344442] SERVICE ALERT: INF-HN8-HNIP41901HW24-20.26.48.50;check_sw_huawei_cpu;UNKNOWN;SOFT;1;UNKNOW: Host not responding to SNMP",
      "[1549344442] SERVICE ALERT: BTHT1-HNIP18501HW24-20.10.15.50;check_interface_huawei: 10;OK;HARD;1;OK-PORT UP: XGigabitEthernet0/0/5#DWL-HNIP18501GC57-E0/1",
      // Bras
      "[1550204103] SERVICE ALERT: BTHT3-HNIP06701PWDA8U-25.41.10.2;FTN Power DongAH Lost;CRITICAL;SOFT;1;Cup dien - ACV = 0: AC-input=0, DC-output=49.9, Load curr=5, Batt curr=-5, Batt remain=100, Batt curr limit=10, Batt Temp=22.4",
      "[1558573095] SERVICE ALERT: HCM-MP-01-01-118.69.255.83;LASER JUNIPER: 7135;WARNING;SOFT;2;WARNING: xe-1/2/0 Laser rx power: [0.03] rx power warning threshold[-20.0 : -18.01] or [0.0 : 1.0]",
      "[1558573100] SERVICE ALERT: NOC-NET-HCM-MP-Backup-01-118.69.255.83;LASER JUNIPER: 7135;WARNING;SOFT;2;WARNING: xe-1/2/0 Laser rx power: [0.03] rx power warning threshold[-20.0 : -18.01] or [0.0 : 1.0]",
      // PE
      "[1520408014] SERVICE ALERT: NOC-NET-HNI-PE-05-01;Check juniper interface queue drop: 8887;OK;HARD;1;OK: xe-1/3/6 - L2#B2B-VPLS#HN-MP05-1-xe-4/1/1 ==queue ok",
      // GW
      "[1520408014] SERVICE ALERT: HCM-AggGW-01;Check juniper interface queue drop: 8887;OK;HARD;1;OK: xe-1/3/6 - L2#B2B-VPLS#HN-MP05-1-xe-4/1/1 ==queue ok",
      "[1520408014] SERVICE ALERT: HCM-DCGW-EPZ-01;Check juniper interface queue drop: 8887;OK;HARD;1;OK: xe-1/3/6 - L2#B2B-VPLS#HN-MP05-1-xe-4/1/1 ==queue ok",
      "[1520408014] SERVICE ALERT: HCM-LLGW-01;Check juniper interface queue drop: 8887;OK;HARD;1;OK: xe-1/3/6 - L2#B2B-VPLS#HN-MP05-1-xe-4/1/1 ==queue ok",
      // CGNAT
      "[1520408014] SERVICE ALERT: HCM-CGNAT-01;Check juniper interface queue drop: 8887;OK;HARD;1;OK: xe-1/3/6 - L2#B2B-VPLS#HN-MP05-1-xe-4/1/1 ==queue ok",
      "[1520408014] SERVICE ALERT: HN-CGNAT-01;Check juniper interface queue drop: 8887;OK;HARD;1;OK: xe-1/3/6 - L2#B2B-VPLS#HN-MP05-1-xe-4/1/1 ==queue ok",
      // SMC
      "[1520408014] SERVICE ALERT: DNG-SMC-01;Check juniper interface queue drop: 8887;OK;HARD;1;OK: xe-1/3/6 - L2#B2B-VPLS#HN-MP05-1-xe-4/1/1 ==queue ok",
      // ignore
      "[1520408014] SERVICE ALERT: DIS-SW-EPZ-MP04-01-10.245.0.115;Check juniper interface queue drop: 8887;OK;HARD;1;OK: xe-1/3/6 - L2#B2B-VPLS#HN-MP05-1-xe-4/1/1 ==queue ok",
      "[1520408014] SERVICE ALERT: DIS-SW-GVP-MP04-02-10.245.0.243;Check juniper interface queue drop: 8887;OK;HARD;1;OK: xe-1/3/6 - L2#B2B-VPLS#HN-MP05-1-xe-4/1/1 ==queue ok",
      "[1520408014] SERVICE ALERT: DIS-SW-MP01-P013-01-10.245.0.113;Check juniper interface queue drop: 8887;OK;HARD;1;OK: xe-1/3/6 - L2#B2B-VPLS#HN-MP05-1-xe-4/1/1 ==queue ok",
      //power
      "[1548637198] SERVICE ALERT: INF-QNH-QNHP08701PWEN1U-20.145.10.100;1.INF_Power_Status;UNKNOWN;HARD;1;UNKNOW: Host not responding to SNMP request",
      "[1548637199] SERVICE ALERT: INF-STG-STGP01701PWEN1U-11.83.141.171;3.INF_Power_Lost;UNKNOWN;SOFT;1;Unknown return status from plugin:1",
      "[1548637199] SERVICE ALERT: INF-DLK-DLKP02401PWEN1U-11.47.141.52;2.INF_Power_Alarm;OK;SOFT;2;OK",
      "[1548637199] SERVICE ALERT: INF-HUE-HUEP00101PWEN8U-10.10.164.230;2.INF_Power_Alarm;OK;SOFT;2;OK",
      "[1548637181] SERVICE ALERT: INF-HN11-HNIP46101PWEN1U-25.35.35.2;1.INF_Power_Status;OK;SOFT;2;AC-Input=241.0, DC-Output=54.18, System-Curr=38, Load-Curr=38, Batt-Curr=0, Batt-Remain=100, Batt-Temp=22.5, Rectnumber=#N/A, Battery-Type=#N/A, Batt-Curr-Limit=#N/A",
      // OTS
      "[1572483581] SERVICE ALERT: QNM.TKY.02;Suy hao Cable C VNR DNG-TKY  Open ticket HT;OK;HARD;1;OK: -254 (Threshold: warning -294.0 critical -314.0)",
      "[1572497352] SERVICE ALERT: DNG.DNG.02-VP;Mat tin hieu Cable B FPT HUE-DNG;CRITICAL;SOFT;1;SNMP CRITICAL - Cable_is_broken *430*"
    )

    log.map {_ match {
      case Opsview.REGEX_BRAS_ID(ts, brasId) => Some(brasId, "bras")
      case Opsview.REGEX_SWITCH(ts, switchId) => Some(switchId, "switch")
      case Opsview.REGEX_HOST(ts, hostId) => Some(hostId, "host")
      case Opsview.REGEX_PE(ts, peId) => {
        val deviceType =
          if (OpsviewDeviceMapper.GW.contains(peId.take(3)))
            "gw"
          else
            "pe"
        Some(peId, deviceType)
      }
      case Opsview.REGEX_MC_SMC(ts, smc) => Some(smc, "smc")
      case Opsview.REGEX_GW(ts, gw) => Some(gw, "gw")
      case Opsview.REGEX_CGNAT(ts, cgnat) => Some(cgnat, "cgnat")
      case Opsview.REGEX_POWER(ts, power) => Some(power, "power")
      case Opsview.REGEX_OTS(ts, ots) => Some(ots, "ots")
      case _ => None
    }
    }.foreach(println)
  }

}
