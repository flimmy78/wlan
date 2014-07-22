#include<ieee80211_openessid.h>

//#define OPENESSID_DEBUG
int openessid_debug = 0;

#ifdef OPENESSID_DEBUG
#define dbg_print(fmt , arg ...) printk("Oop:"fmt,##arg)
#else
#define dbg_print(fmt,arg ...) do{    \
	if(openessid_debug)               \
		printk("Oop:"fmt,##arg);      \
}while(0)                             \

#endif
extern u_int32_t openessid_param;  /* lmac/ath_dev/ath_config.c */

struct ieee80211_essid_table g_essid_table[IEEE80211_STORE_ESSID];

extern char openessid_whitelist[8][32];
extern char openessid_blacklist[32][32];
extern int whitelist_cnt ;
extern int blacklist_cnt ;

int ieee80211_check_essid(struct ieee80211vap *vap, char *essid, u_int32_t len)
{
	struct ieee80211_scan_entry *entry, *next;


	if(!(openessid_param & OPENESSID_SCAN_AP_MASK))
		return 0;

	ieee80211_scan_table_t table = ieee80211_vap_get_scan_table(vap);

	if(table == NULL)
		return 0;

	spin_lock(&(table->st_lock));
	TAILQ_FOREACH_SAFE(entry, &(table->st_entry), se_list, next){

		if(len != entry->se_ssid[1])
			continue;

		if(OS_MEMCMP(essid , entry->se_ssid + 2, entry->se_ssid[1]) == 0){
			dbg_print(" match ESSID {%s} by scanning\n", essid);
			spin_unlock(&(table->st_lock));
			return 1;
		}
	}
	spin_unlock(&(table->st_lock));
	return 0;
}

void ieee80211_essid_delete(int index)
{
	int i;
	struct ieee80211vap *vap = g_essid_table[index].vap;

	dbg_print("Timeout ! delete [%d]{%s} ESSID\n",index, g_essid_table[index].essid);

	for(i = 0; i < IEEE80211_STORE_VAP_ESSID; i++)
	{
		if(vap->iv_essid_index[i] == index){
			vap->iv_essid_index[i] = -1;
			vap->iv_essid_cnt--;
			break;
		}
	}

	OS_MEMSET(&g_essid_table[index], 0, sizeof(struct ieee80211_essid_table));
}

int ieee80211_scan_node(struct ieee80211vap *vap ,char *essid, int len)
{
	struct ieee80211_node_table *nt = &vap->iv_ic->ic_sta;
	struct ieee80211_node *ni;

	TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
		if(OS_MEMCMP(ni->ni_essid, essid, len) == 0){
			return 1;
		}
	}
	return 0;

}

void update_whitelist_tag(struct ieee80211vap *vap ,int index)
{
	int i = 0;
	vap->iv_whitelist_tag[index] = vap->iv_whitelist_tag[4];

	if(++vap->iv_whitelist_tag[4] == whitelist_cnt)
		vap->iv_whitelist_tag[4] = 0;

	while(1)
	{
		for(i = 0; i < 4; i++)
		{
			if(vap->iv_whitelist_tag[4] == vap->iv_whitelist_tag[i]){
				vap->iv_whitelist_tag[4]++;
				break;
			}
		}
		if(i == 4)
			break;

	}
}

void ieee80211_update_whitelist(struct ieee80211vap *vap, int index)
{
	int whitelist_tag = vap->iv_whitelist_tag[4];

	dbg_print("whitelist Timeout ! delete [%d]{%s} ESSID\n",index, g_essid_table[index].essid);

	OS_MEMSET(&g_essid_table[index], 0, sizeof(struct ieee80211_essid_table));

	OS_MEMCPY(g_essid_table[index].essid, openessid_whitelist[whitelist_tag],
			strlen(openessid_whitelist[whitelist_tag]));

	g_essid_table[index].len = strlen(openessid_whitelist[whitelist_tag]);
	g_essid_table[index].last_time = jiffies;


	update_whitelist_tag(vap, index);
}
void ieee80211_check_whitelist(struct ieee80211vap *vap, char *essid, u_int32_t len)
{
	int i, j, t;
	u_int32_t timeout;

	if(0 == essid[0])
		return;

	/* timeout knick out */
	for(i = 0; i < 4; i++)
	{
		timeout = jif2sec(jiffies) - jif2sec(g_essid_table[i].last_time);

		if(timeout >= (openessid_param & OPENESSID_TIMEOUT_MASK) 
				//&& (g_essid_table[i].sta_cnt <= 0)
				&& (ieee80211_scan_node(vap, g_essid_table[i].essid, g_essid_table[i].len) == 0)    /* hasn't station */
				&& (OS_MEMCMP(essid, g_essid_table[i].essid, g_essid_table[i].len) != 0)  /* current probe dismatched */
				|| ieee80211_check_essid(vap, g_essid_table[i].essid, len) != 0){

			ieee80211_update_whitelist(vap, i);

		}else if(OS_MEMCMP(essid, g_essid_table[i].essid, g_essid_table[i].len) == 0){
			g_essid_table[i].last_time = jiffies;
		}
	}

	if(ieee80211_check_essid(vap, essid, len) != 0) 
		return;

	for(i = 0; i < 4; i++)
	{
		if(OS_MEMCMP(g_essid_table[i].essid, essid, len) == 0){

			g_essid_table[i].probe_cnt ++;
			g_essid_table[i].last_time = jiffies;
			return;
		}

	}
	return ;

}
void ieee80211_save_essid(struct ieee80211vap *vap, char *essid,
		u_int32_t len, char *mac )
{
	int i, j, t;
	u_int32_t timeout;

	if(0 == essid[0])
		return;

	/* timeout knick out */
	for(i = 0; i < IEEE80211_STORE_ESSID; i++)
	{
		if(g_essid_table[i].vap == NULL)
			continue;

		timeout = jif2sec(jiffies) - jif2sec(g_essid_table[i].last_time);

		if(timeout >= (openessid_param & OPENESSID_TIMEOUT_MASK) 
				//&& (g_essid_table[i].sta_cnt <= 0)
				&& (ieee80211_scan_node(vap, g_essid_table[i].essid, g_essid_table[i].len) == 0)    /* hasn't station */
				&& (OS_MEMCMP(essid, g_essid_table[i].essid, g_essid_table[i].len) != 0)  /* current probe dismatched */
				|| ieee80211_check_essid(vap, g_essid_table[i].essid, len) != 0){

			ieee80211_essid_delete(i);

		}else if(OS_MEMCMP(essid, g_essid_table[i].essid, g_essid_table[i].len) == 0){

			g_essid_table[i].last_time = jiffies;

		}
	}
	/* timeout knick out end */

	if(ieee80211_check_essid(vap, essid, len) != 0) 
		return;

	if(vap->iv_essid_cnt >= IEEE80211_STORE_VAP_ESSID)
	{
		return;
	}


	for(i = 0; i < IEEE80211_STORE_ESSID; i++)
	{
		if(g_essid_table[i].vap == NULL)
			continue;

		if(OS_MEMCMP(g_essid_table[i].essid, essid, len) == 0){
			dbg_print(" {%s} ESSID has be registered\n",essid);
			g_essid_table[i].probe_cnt ++;
			g_essid_table[i].last_time = jiffies;
			return;
		}
	}

	/* XXX no found in the table, so register */
	if(i == IEEE80211_STORE_ESSID){
		for(j = 0; j < IEEE80211_STORE_ESSID; j++){
			if(g_essid_table[j].vap == NULL){
				dbg_print(" register {%s} ESSID in the table\n",essid);
				OS_MEMCPY(g_essid_table[j].essid, essid, len);
				g_essid_table[j].len = len;
				g_essid_table[j].probe_cnt++;
				g_essid_table[j].vap = vap;
				g_essid_table[j].last_time = jiffies;

				for (t = 0; t < IEEE80211_STORE_VAP_ESSID; t++)
				{
					if(vap->iv_essid_index[t] == -1){
						vap->iv_essid_index[t] = j;
						vap->iv_essid_cnt++;
						break;
					}
				}
				return;
			}
		}

	}
}

int ieee80211_verify_openssid(struct ieee80211vap *vap,struct ieee80211_node *ni, char *ssid)
{
	int i;
	int index;
	if(ssid[1] <= 0 || vap->iv_essid_cnt <= 0 )
		return 0;

	for(i = 0; i < IEEE80211_STORE_VAP_ESSID; i++)
	{
		index = vap->iv_essid_index[i];
		if(index < 0)
			continue;

		if(OS_MEMCMP(g_essid_table[index].essid, ssid + 2, ssid[1]) == 0)
		{
			dbg_print(" {%s} ESSID asreq match\n",g_essid_table[index].essid);

			g_essid_table[index].sta_cnt++;

			if(ni != vap->iv_bss){
				OS_MEMCPY(ni->ni_essid, ssid + 2, ssid[1]);
				ni->ni_esslen = ssid[1];
			}

			return 1;
		}
	}

	return 0;
}

void node_free_openessid(struct ieee80211vap *vap, struct ieee80211_node *ni)
{
	int i,index;


#if 0 
	if(!(openessid_param & OPENESSID_ENABLE_MASK)){
		return;
	}

#endif
	if(ni != vap->iv_bss)
	{
		for(i = 0; i < IEEE80211_STORE_VAP_ESSID; i++)
		{
			index = vap->iv_essid_index[i];

			if(index < 0)
				continue;

			if(OS_MEMCMP(ni->ni_essid, g_essid_table[index].essid, g_essid_table[index].len) != 0){

				continue;

			}else{
				g_essid_table[index].sta_cnt--;
				break;
			}

		}

	}
	return;
}

void init_openessid(struct ieee80211vap *vap)
{

	int i;

	for(i = 0; i < IEEE80211_STORE_VAP_ESSID; i++)
		vap->iv_essid_index[i] = -1;

	vap->iv_essid_cnt    = 0;
	vap->iv_essid_be_cnt = 0;

	memset(&g_essid_table, 0, sizeof(g_essid_table));
}

void get_vap_openessid_info(struct ieee80211vap *vap)
{
	int i,index;

	struct ieee80211_node_table *nt = &vap->iv_ic->ic_sta;
	struct ieee80211_node *ni;
	const char *status[] = {"enable", "disable"};

	printk("whitelist_duty : %d - %s\n", vap->iv_whitelist_duty,
			vap->iv_whitelist_duty?status[0]:status[1]);

	if(!(openessid_param & OPENESSID_ENABLE_MASK)){
		printk("Warning: openessid is off\n");
		//return;
	}

	for(i = 0; i < IEEE80211_STORE_VAP_ESSID; i++)
	{
		index = vap->iv_essid_index[i];

		if(index < 0)
			continue;
		printk("Tag 2 \n");

		/* need for fixing node list bug */
		if(g_essid_table[index].len <= 0)
		{
			printk("Tag 3 \n");
			vap->iv_essid_index[i] = -1;
			continue;
		}

		printk("%d) ESSID: %s\n", index, g_essid_table[index].essid);

		TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
			if(OS_MEMCMP(ni->ni_essid, g_essid_table[index].essid, g_essid_table[index].len) == 0)
			{
				printk("\tMAC : %02x-%02x-%02x-%02x-%02x-%02x\n",
						ni->ni_macaddr[0],
						ni->ni_macaddr[1],
						ni->ni_macaddr[2],
						ni->ni_macaddr[3],
						ni->ni_macaddr[4],
						ni->ni_macaddr[5]);
			}
		}
		printk("\n");
	}

	if(openessid_debug){
		printk("----------------------------------------------\n");
		printk("Node List ...\n");
		TAILQ_FOREACH(ni, &nt->nt_node, ni_list){
			printk("MAC : %02x-%02x-%02x-%02x-%02x-%02x ==> %s\n",
					ni->ni_macaddr[0],
					ni->ni_macaddr[1],
					ni->ni_macaddr[2],
					ni->ni_macaddr[3],
					ni->ni_macaddr[4],
					ni->ni_macaddr[5],
					ni->ni_essid);
		}
	}

}
EXPORT_SYMBOL(get_vap_openessid_info);

void init_whitelist(struct ieee80211vap *vap)
{
	int i;
	if(whitelist_cnt < 4){

		vap->iv_whitelist_duty = 0;
		printk("whitelist is less than 4, panic error !\n");
		return;

	}else{

		for( i = 0; i < 4; i++){
			OS_MEMCPY(g_essid_table[i].essid, openessid_whitelist[i],
					strlen(openessid_whitelist[i]));
			g_essid_table[i].len = strlen(openessid_whitelist[i]);
			g_essid_table[i].last_time = jiffies;

			if(vap->iv_whitelist_duty == 1)
				g_essid_table[i].vap = vap;
		}
	}

	if(vap->iv_whitelist_duty == 1)
	{
		for(i = 0; i < IEEE80211_STORE_VAP_ESSID; i++){
			printk("Tag 1\n");
			vap->iv_essid_index[i] = i;
		}

		vap->iv_whitelist_tag[0] = 0;
		vap->iv_whitelist_tag[1] = 1;
		vap->iv_whitelist_tag[2] = 2;
		vap->iv_whitelist_tag[3] = 3;
		vap->iv_whitelist_tag[4] = 4;
	}

}
EXPORT_SYMBOL(init_whitelist);
