/*
 *  Copyright (c) 2008 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  management processing code common for IBSS and AP.
 */

#include "ieee80211_mlme_priv.h"

/* AUTELAN-Added-Begin : &tuqiang for openessid*/
char current_essid[IEEE80211_NWID_LEN ] = {0};
extern void ieee80211_save_essid(struct ieee80211vap *vap, char *essid,
		u_int32_t len, char *mac );

extern void ieee80211_check_whitelist(struct ieee80211vap *vap, char *essid,u_int32_t len);
extern u_int32_t openessid_param;
/* AUTELAN-Added-End : tuqiang@autelan.com */

#if UMAC_SUPPORT_AP || UMAC_SUPPORT_IBSS || UMAC_SUPPORT_BTAMP
/*
 * Send a probe response frame.
 * NB: for probe response, the node may not represent the peer STA.
 * We could use BSS node to reduce the memory usage from temporary node.
 */
int
ieee80211_send_proberesp(struct ieee80211_node *ni, u_int8_t *macaddr,
                         const void *optie, const size_t  optielen)
{
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211_rsnparms *rsn = &vap->iv_rsn;
    wbuf_t wbuf;
    struct ieee80211_frame *wh;
    u_int8_t *frm;
    u_int16_t capinfo;
    int enable_htrates;
    bool add_wpa_ie = true;

    ASSERT(vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_IBSS ||
           vap->iv_opmode == IEEE80211_M_BTAMP);
    
    wbuf = wbuf_alloc(ic->ic_osdev, WBUF_TX_MGMT, MAX_TX_RX_PACKET_SIZE);
    if (wbuf == NULL)
        return -ENOMEM;

#ifdef IEEE80211_DEBUG_REFCNT
    printk("%s ,line %u: increase node %p <%s> refcnt to %d\n",
           __func__, __LINE__, ni, ether_sprintf(ni->ni_macaddr),
           ieee80211_node_refcnt(ni));
#endif
    
    /* setup the wireless header */
    wh = (struct ieee80211_frame *)wbuf_header(wbuf);
    ieee80211_send_setup(vap, ni, wh,
                         IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP,
                         vap->iv_myaddr, macaddr,
                         ieee80211_node_get_bssid(ni));
    frm = (u_int8_t *)&wh[1];

    /*
     * probe response frame format
     *  [8] time stamp
     *  [2] beacon interval
     *  [2] cabability information
     *  [tlv] ssid
     *  [tlv] supported rates
     *  [tlv] parameter set (FH/DS)
     *  [tlv] parameter set (IBSS)
     *  [tlv] extended rate phy (ERP)
     *  [tlv] extended supported rates
     *  [tlv] country (if present)
     *  [3] power constraint
     *  [tlv] WPA
     *  [tlv] WME
     *  [tlv] HT Capabilities
     *  [tlv] HT Information
     *      [tlv] Atheros Advanced Capabilities
     */
    OS_MEMZERO(frm, 8);  /* timestamp should be filled later */
    frm += 8;
    *(u_int16_t *)frm = htole16(vap->iv_bss->ni_intval);
    frm += 2;
    if (vap->iv_opmode == IEEE80211_M_IBSS)
        capinfo = IEEE80211_CAPINFO_IBSS;
    else
        capinfo = IEEE80211_CAPINFO_ESS;
    if (IEEE80211_VAP_IS_PRIVACY_ENABLED(vap))
        capinfo |= IEEE80211_CAPINFO_PRIVACY;
    if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
        IEEE80211_IS_CHAN_2GHZ(ic->ic_curchan))
        capinfo |= IEEE80211_CAPINFO_SHORT_PREAMBLE;
    if (ic->ic_flags & IEEE80211_F_SHSLOT)
        capinfo |= IEEE80211_CAPINFO_SHORT_SLOTTIME;
    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap))
        capinfo |= IEEE80211_CAPINFO_SPECTRUM_MGMT;
    *(u_int16_t *)frm = htole16(capinfo);
    frm += 2;
    
	/* AUTELAN-Added-Begin : &tuqiang for openessid*/
#if 0 
	frm = ieee80211_add_ssid(frm, vap->iv_bss->ni_essid,
			vap->iv_bss->ni_esslen);
#endif
	if(openessid_param & OPENESSID_ENABLE_MASK){

		if(current_essid[0] == 0){
			frm = ieee80211_add_ssid(frm, vap->iv_bss->ni_essid,
					vap->iv_bss->ni_esslen);
		}else{
			frm = ieee80211_add_ssid(frm, current_essid,
					strlen(current_essid));
			memset(current_essid, 0, sizeof(current_essid));
		}
	}
	else{
		frm = ieee80211_add_ssid(frm, vap->iv_bss->ni_essid,
				vap->iv_bss->ni_esslen);
	}
	/* AUTELAN-Added-End : tuqiang@autelan.com */
    
    frm = ieee80211_add_rates(frm, &vap->iv_bss->ni_rates, ic);

    if (!IEEE80211_IS_CHAN_FHSS(vap->iv_bsschan)) {
        *frm++ = IEEE80211_ELEMID_DSPARMS;
        *frm++ = 1;
        *frm++ = ieee80211_chan2ieee(ic, ic->ic_curchan);
    }
    
    if (vap->iv_opmode == IEEE80211_M_IBSS) {
        *frm++ = IEEE80211_ELEMID_IBSSPARMS;
        *frm++ = 2;
        *frm++ = 0; *frm++ = 0;     /* TODO: ATIM window */
    }

    if (IEEE80211_IS_COUNTRYIE_ENABLED(ic)) {
        frm = ieee80211_add_country(frm, vap);
    }

    if (ieee80211_ic_doth_is_set(ic) && ieee80211_vap_doth_is_set(vap)) {
        *frm++ = IEEE80211_ELEMID_PWRCNSTR;
        *frm++ = 1;
        *frm++ = IEEE80211_PWRCONSTRAINT_VAL(vap);
    }
   
#if ATH_SUPPORT_IBSS_DFS
    if (vap->iv_opmode == IEEE80211_M_IBSS) {
         frm =  ieee80211_add_ibss_dfs(frm,vap);
    }
#endif

    if (IEEE80211_IS_CHAN_ANYG(ic->ic_curchan) || 
        IEEE80211_IS_CHAN_11NG(ic->ic_curchan)) {
        frm = ieee80211_add_erp(frm, ic);
    }

    /*
     * check if os shim has setup RSN IE it self.
     */
    IEEE80211_VAP_LOCK(vap);
    if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length) {
        add_wpa_ie = ieee80211_check_wpaie(vap, vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].ie,
                                           vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length);
    }
    if (vap->iv_opt_ie.length) {
        add_wpa_ie = ieee80211_check_wpaie(vap, vap->iv_opt_ie.ie,
                                           vap->iv_opt_ie.length);
    }
    IEEE80211_VAP_UNLOCK(vap);

    if (add_wpa_ie) {
        if (RSN_AUTH_IS_RSNA(rsn))
            frm = ieee80211_setup_rsn_ie(vap, frm);
    }

#if ATH_SUPPORT_WAPI
    if (RSN_AUTH_IS_WAI(rsn))
        frm = ieee80211_setup_wapi_ie(vap, frm);
#endif

    frm = ieee80211_add_xrates(frm, &vap->iv_bss->ni_rates, ic);

    enable_htrates = ieee80211vap_htallowed(vap);
    
    if (IEEE80211_IS_CHAN_11N(ic->ic_curchan) && enable_htrates) {
        frm = ieee80211_add_htcap(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);

        if (!IEEE80211_IS_HTVIE_ENABLED(ic))
            frm = ieee80211_add_htcap_pre_ana(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);

        frm = ieee80211_add_htinfo(frm, ni);

        if (!IEEE80211_IS_HTVIE_ENABLED(ic))
            frm = ieee80211_add_htinfo_pre_ana(frm, ni);

        if (!(ic->ic_flags & IEEE80211_F_COEXT_DISABLE)) {
            frm = ieee80211_add_obss_scan(frm, ni);
            frm = ieee80211_add_extcap(frm, ni);
        }
    }

    if (add_wpa_ie) {
        if (RSN_AUTH_IS_WPA(rsn))
            frm = ieee80211_setup_wpa_ie(vap, frm);
    }
    
    if (ieee80211_vap_wme_is_set(vap) &&
        (vap->iv_opmode == IEEE80211_M_HOSTAP || vap->iv_opmode == IEEE80211_M_BTAMP)) /* don't support WMM in ad-hoc for now */
        frm = ieee80211_add_wme_param(frm, &ic->ic_wme, IEEE80211_VAP_IS_UAPSD_ENABLED(vap));

    if ((IEEE80211_IS_CHAN_11N(ic->ic_curchan)) && (IEEE80211_IS_HTVIE_ENABLED(ic)) && enable_htrates) {
        frm = ieee80211_add_htcap_vendor_specific(frm, ni, IEEE80211_FC0_SUBTYPE_PROBE_RESP);
        frm = ieee80211_add_htinfo_vendor_specific(frm, ni);
    }

    if (vap->iv_bss->ni_ath_flags) {
        frm = ieee80211_add_athAdvCap(frm, vap->iv_bss->ni_ath_flags,
                                      vap->iv_bss->ni_ath_defkeyindex);
    } else {
        frm = ieee80211_add_athAdvCap(frm, 0, IEEE80211_INVAL_DEFKEY);
    }

    /* Insert ieee80211_ie_ath_extcap IE to beacon */
    if (ic->ic_ath_extcap)
        frm = ieee80211_add_athextcap(frm, ic->ic_ath_extcap, ic->ic_weptkipaggr_rxdelim);

#ifdef notyet
    if (ni->ni_ath_ie != NULL)    /* XXX */
        frm = ieee80211_add_ath(frm, ni);
#endif
    
    IEEE80211_VAP_LOCK(vap);
    if (vap->iv_opt_ie.length) {
        OS_MEMCPY(frm, vap->iv_opt_ie.ie,
                  vap->iv_opt_ie.length);
        frm += vap->iv_opt_ie.length;
    }

    if (vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length) {
        OS_MEMCPY(frm, vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].ie,
                  vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length);
        frm += vap->iv_app_ie[IEEE80211_FRAME_TYPE_PROBERESP].length;
    }

    /* Add the Application IE's */
    frm = ieee80211_mlme_app_ie_append(vap, IEEE80211_FRAME_TYPE_PROBERESP, frm);
    IEEE80211_VAP_UNLOCK(vap);
    
    if (optie != NULL && optielen != 0) {
        OS_MEMCPY(frm, optie, optielen);
        frm += optielen;
    }

    wbuf_set_pktlen(wbuf, (frm - (u_int8_t *)wbuf_header(wbuf)));

    return ieee80211_send_mgmt(vap,ni, wbuf,true);
}

int
ieee80211_recv_probereq(struct ieee80211_node *ni, wbuf_t wbuf, int subtype)
{
    struct ieee80211com *ic = ni->ni_ic;
    struct ieee80211vap *vap = ni->ni_vap;
    struct ieee80211_frame *wh;
    u_int8_t *frm, *efrm;
    u_int8_t *ssid, *rates, *ven;

#if ATH_SUPPORT_AP_WDS_COMBO
    if (vap->iv_opmode == IEEE80211_M_STA || !ieee80211_vap_ready_is_set(vap) || vap->iv_no_beacon) {
#else
    if (vap->iv_opmode == IEEE80211_M_STA || !ieee80211_vap_ready_is_set(vap)) {
#endif
        vap->iv_stats.is_rx_mgtdiscard++;   /* XXX stat */
        return -EINVAL;
    }
	/*duanmingzhe modify for sta assoc fail*/
	if(ni != vap->iv_bss)
	{	
		ni = vap->iv_bss;
	}
	/*duanmingzhe modify end*/
    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    frm = (u_int8_t *)&wh[1];
    efrm = wbuf_header(wbuf) + wbuf_get_pktlen(wbuf);

	/*Begin:Modified by zhaoyang1 for judging unicast or multicast probe req based on essid 2013-04-27*/
	#if 0
	/*zhaoyang1 add start for  probe request REQUIREMENTS-340*/
	if (vap->iv_probe_request) {
		switch (vap->iv_probe_request) {
			case IEEE80211_BROADCAST_PROBE:
				if (IEEE80211_IS_BROADCAST(wh->i_addr1)) {
					vap->iv_stats.is_rx_mgtdiscard++;   /* XXX stat */
			        return -EINVAL;
				}
				break;
			case IEEE80211_ALL_PROBE:
				vap->iv_stats.is_rx_mgtdiscard++;   /* XXX stat */
	    		return -EINVAL;
			default:
				printk("Probe_req value is wrong, iv_probe_request = %d\n", vap->iv_probe_request);
				break;
		}
	}
	/*zhaoyang1 add end*/
	/*End:Modified by zhaoyang1 for judging unicast or multicast probe req based on essid 2013-04-27*/
	#endif
	if (IEEE80211_IS_MULTICAST(wh->i_addr2)) {
        /* frame must be directed */
        vap->iv_stats.is_rx_mgtdiscard++;   /* XXX stat */
        return -EINVAL;
    }

    /*
     * prreq frame format
     *  [tlv] ssid
     *  [tlv] supported rates
     *  [tlv] extended supported rates
     *  [tlv] Atheros Advanced Capabilities
     */
    ssid = rates = NULL;
    while (((frm+1) < efrm) && (frm + frm[1] + 1 < efrm)) {
        switch (*frm) {
        case IEEE80211_ELEMID_SSID:
            ssid = frm;
			/*Begin:Modified by zhaoyang1 for judging unicast or multicast probe req based on essid 2013-04-27*/
			if (vap->iv_probe_request) {
				switch (vap->iv_probe_request) {
					case IEEE80211_BROADCAST_PROBE:
						if (*(ssid+1) == 0) {
							vap->iv_stats.is_rx_mgtdiscard++;   /* XXX stat */
							return -EINVAL;
						}
					break;
					case IEEE80211_ALL_PROBE:
						vap->iv_stats.is_rx_mgtdiscard++;   /* XXX stat */
						return -EINVAL;
					default:
						printk("Probe_req value is wrong, iv_probe_request = %d\n", vap->iv_probe_request);
						break;
				}
			}
			/*End:Modified by zhaoyang1 for judging unicast or multicast probe req based on essid 2013-04-27*/
            break;
        case IEEE80211_ELEMID_RATES:
            rates = frm;
            break;
        case IEEE80211_ELEMID_VENDOR:
            if (vap->iv_venie && vap->iv_venie->ven_oui_set) {            
                ven = frm;
                if (ven[2] == vap->iv_venie->ven_oui[0] && 
                    ven[3] == vap->iv_venie->ven_oui[1] && 
                    ven[4] == vap->iv_venie->ven_oui[2]) {
                    vap->iv_venie->ven_ie_len = MIN(ven[1] + 2, IEEE80211_MAX_IE_LEN);
                    OS_MEMCPY(vap->iv_venie->ven_ie, ven, vap->iv_venie->ven_ie_len);
                }
            }
            break;
        }
        frm += frm[1] + 2;
    }

    if (frm > efrm) {
        return -EINVAL;
    }

    IEEE80211_VERIFY_ELEMENT(rates, IEEE80211_RATE_MAXSIZE);
    IEEE80211_VERIFY_ELEMENT(ssid, IEEE80211_NWID_LEN);
	/* AUTELAN-Added-Begin : &tuqiang for openessid */

#if 0 
    IEEE80211_VERIFY_SSID(vap->iv_bss, ssid);
#endif
	if(openessid_param & OPENESSID_ENABLE_MASK){
		if (ssid[1] != 0 && ssid[1] < 32)
		{
			if(OS_MEMCMP(vap->iv_bss->ni_essid, ssid + 2, ssid[1]) != 0)
			{
				OS_MEMCPY(current_essid, ssid + 2, ssid[1]);
				current_essid[ssid[1]] = '\0';
				if(vap->iv_whitelist_duty == 0)
					ieee80211_save_essid(vap, current_essid, ssid[1], wh->i_addr2);
				else
					ieee80211_check_whitelist(vap, current_essid, ssid[1]);
			}

		}else{
			return -EINVAL;
		}
	}else{
		IEEE80211_VERIFY_SSID(vap->iv_bss, ssid);
	}

	/* AUTELAN-Added-End : tuqiang@autelan.com */


    if (IEEE80211_VAP_IS_HIDESSID_ENABLED(vap) && (ssid[1] == 0)) {
        IEEE80211_DISCARD(vap, IEEE80211_MSG_INPUT,
                          wh, ieee80211_mgt_subtype_name[
                              subtype >> IEEE80211_FC0_SUBTYPE_SHIFT],
                          "%s", "no ssid with ssid suppression enabled");
        vap->iv_stats.is_rx_ssidmismatch++; /*XXX*/
        return -EINVAL;
    }

    /*
     * Skip Probe Requests received while the scan algorithm is setting a new 
     * channel, or while in a foreign channel.
     * Trying to transmit a frame (Probe Response) during a channel change 
     * (which includes a channel reset) can cause a NMI due to invalid HW 
     * addresses. 
     * Trying to transmit the Probe Response while in a foreign channel 
     * wouldn't do us any good either.
     */
    if (ieee80211_scan_can_transmit(ic->ic_scanner))
        ieee80211_send_proberesp(ni, wh->i_addr2, NULL,0);
    
    return 0;
}

#endif
