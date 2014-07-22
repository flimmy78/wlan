#ifndef _IEEE80211_OPENESSID_H
#define _IEEE80211_OPENESSID_H

#define IEEE80211_STORE_ESSID          64

#define IEEE80211_STORE_VAP_ESSID      4

#define IEEE80211_STORE_ESSID_TIMEOUT  10

#define jif2sec(x)         (x / 250)

/* openessid_mask datail form . bits (0 - 19)
^--------------------------------------------------------------------------------------------------------------^
|      0 - 7    |  8 - 10  |        11       |  12 - 14  |          15         |  16 - 18  |         19        |
 --------------------------------------------------------------------------------------------------------------
|    timeout    |    xxx   | scan ap switch  |    xxx    | data forward switch |    xxx    | OPE enable switch |
^--------------------------------------------------------------------------------------------------------------^
*/

#define OPENESSID_TIMEOUT_MASK         0xff
#define OPENESSID_SCAN_AP_MASK         0x800
#define OPENESSID_DATA_FORWARD_MASK    0x8000
#define OPENESSID_ENABLE_MASK          0x80000

struct ieee80211_essid_table{

	char essid[32 + 1];
	u_int32_t len;
	char macaddr[6];
	struct ieee80211vap *vap;
	u_int32_t probe_cnt;
	u_int32_t last_time;
	u_int32_t sta_cnt;
}; 

#endif
