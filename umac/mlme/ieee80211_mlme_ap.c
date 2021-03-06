/*
 * Copyright (c) 2010, Atheros Communications Inc.
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
 */

#include "ieee80211_mlme_priv.h"    /* Private to MLME module */
#include <ieee80211_target.h>
#include <ieee80211_smartantenna.h>

#if UMAC_SUPPORT_AP || UMAC_SUPPORT_BTAMP

/*Start: added by zhanghu for increasing rate*/
void mlme_handle_rate_mask_by_curmode(struct ieee80211com *ic)
{
#ifndef  FOR_BIT
#define FOR_BIT(parm)    (sizeof(parm)*8)
#endif
    /*ngba for four bit*/
    ic->ic_rate_mask &= ~((u_int64_t)0x0F<<(FOR_BIT(ic->ic_rate_mask) - 8)); 
    switch(ic->ic_curmode){
        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_TURBO_A:
        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NA_HT40:
            ic->ic_rate_mask |= (u_int64_t)1 << (FOR_BIT(ic->ic_rate_mask) - 8);  
            if(ic->ic_curmode != IEEE80211_MODE_11A && ic->ic_curmode != IEEE80211_MODE_TURBO_A){
                ic->ic_rate_mask |= (u_int64_t)1 << ((FOR_BIT(ic->ic_rate_mask) - 8) + 3);                  
            }
            break;
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_TURBO_G:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
            ic->ic_rate_mask |= (u_int64_t)1 << ((FOR_BIT(ic->ic_rate_mask) - 8) + 2);  
            if(ic->ic_curmode != IEEE80211_MODE_11G && ic->ic_curmode != IEEE80211_MODE_TURBO_G){
                ic->ic_rate_mask |= (u_int64_t)1 << ((FOR_BIT(ic->ic_rate_mask) - 8) + 3);                                  
            }            
            break;
        case IEEE80211_MODE_11B:
            ic->ic_rate_mask |= (u_int64_t)1 << ((FOR_BIT(ic->ic_rate_mask) - 8) + 1);  
            break;
        case IEEE80211_MODE_AUTO:
        case IEEE80211_MODE_FH:
        default:
            ic->ic_rate_mask |= (u_int64_t)1 << ((FOR_BIT(ic->ic_rate_mask) - 8) + 2);  
    }
    
    return;
}
/*End: added by zhanghu for increasing rate*/

void ieee80211_mlme_recv_assoc_request(struct ieee80211_node *ni,
                                       u_int8_t reassoc,u_int8_t *vendor_ie, wbuf_t wbuf)
{
    struct ieee80211vap           *vap = ni->ni_vap;
    struct ieee80211com           *ic = ni->ni_ic;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    u_int8_t                      newassoc = (ni->ni_associd == 0);
    wbuf_t                        resp_wbuf;
    u_int16_t                     assocstatus;
    ieee80211_mlme_event          event;
    u_int8_t                      node_leave = 0; 

    /* AP  must be up and running */
    if (!mlme_priv->im_connection_up || ieee80211_vap_ready_is_clear(vap)) {
	IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
			" <FAIL> [Step %s - RECV %s REQ] %s: ap isn't up or run\n", 
			reassoc ? "04" : "03", reassoc ? "REASSOC" : "ASSOC", __func__);
        return;
    }
    IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s\n", __func__);

    if (ieee80211_node_join(ni)) {
        /* Association Failure */
        assocstatus = IEEE80211_REASON_ASSOC_TOOMANY;
    } else {
        assocstatus = IEEE80211_STATUS_SUCCESS;

        /* Indicate that a new node has associated */
        event.type = IEEE80211_MLME_EVENT_STA_JOIN;
        event.u.event_sta.sta_count= vap->iv_sta_assoc;
        event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
        event.u.event_sta.ni = ni;
        ieee80211_mlme_deliver_event(mlme_priv,&event);
    }

    /* Clear any previously cached status */
#ifdef ATHR_RNWF
    ni->ni_assocstatus = IEEE80211_STATUS_UNSPECIFIED;
#else
    ni->ni_assocstatus = IEEE80211_STATUS_SUCCESS;
#endif

    /* Setup association response frame before indication */
    resp_wbuf = ieee80211_setup_assocresp(ni, NULL, reassoc, assocstatus);
    if (!resp_wbuf)
        assocstatus = IEEE80211_REASON_UNSPECIFIED;

    /* Move this down after sending the Assoc resp, so that the EAPOL
     * frame that is sent as consequence of this event, doesn't go OTA
     * before the Assoc Resp frame on some partial offload platforms. */
     
/*zhaoyang1 transplant from 717*/
    if (reassoc) {
        IEEE80211_DELIVER_EVENT_MLME_REASSOC_INDICATION(vap, ni->ni_macaddr,
                                                      assocstatus, wbuf, resp_wbuf);
		/*pengruofeng add start for management frame stats 2011-5-9*/
		vap->iv_stats.is_reassocs++;
		/*pengruofeng add end 2011-5-9*/
	}
    if (!reassoc) {
        IEEE80211_DELIVER_EVENT_MLME_ASSOC_INDICATION(vap, ni->ni_macaddr,
                                                    assocstatus, wbuf, resp_wbuf);
		/*pengruofeng add start for management frame stats 2011-5-9*/
		vap->iv_stats.is_assocs++;
		/*pengruofeng add end 2011-5-9*/
	}
/*zhaoyang1 transplant end*/

    /* Memory allocation failure, no point continuing */
    if (!resp_wbuf) {
	 IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
			" <FAIL> [Step %s - RECV %s REQ] %s: resp_wbuf alloc failed\n", 
			reassoc ? "04" : "03", reassoc ? "REASSOC" : "ASSOC", __func__);
        return;
    }

    /* Association rejection from above */
    if (ni->ni_assocstatus != IEEE80211_STATUS_SUCCESS) {

        /* Update already formed association response and send it out */
        ieee80211_setup_assocresp(ni, resp_wbuf, reassoc, ni->ni_assocstatus);
        IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
			" <SEND> [Step %s - SEND %s RESP] %s: Association rejection, ni_assocstatus = %d\n", 
			reassoc ? "04" : "03", reassoc ? "REASSOC" : "ASSOC", __func__, ni->ni_assocstatus);
        ieee80211_send_mgmt(vap,ni, resp_wbuf,false);

/*zhaoyang1 transplant from 717*/
	    ieee80211_node_leave(ni);                                                  
    } 
	else 
    {
		 /*xiaruixin modify for traffic_balance reset*/
		if (thinap && vap->iv_traffic_balance) { //Modified by zhaoyang1 for optimizing traffic balance based wlan 2013-06-19
			IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
				" <INFO> [Step %s - RECV %s REQ] %s: thinap = %d, vap->iv_traffic_balance = %d\n", 
				reassoc ? "04" : "03", reassoc ? "REASSOC" : "ASSOC", __func__, thinap, vap->iv_traffic_balance);
			goto balance_code;
		}
        IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
			" <SEND> [Step %s - SEND %s RESP] %s: send %s response frame\n", 
			reassoc ? "04" : "03", reassoc ? "REASSOC" : "ASSOC", __func__, reassoc ? "reassoc" : "assoc");
		ieee80211_send_mgmt(vap,ni,resp_wbuf,false);
balance_code:
         /*xiaruixin modify end*/
/*zhaoyang1 transplant end*/
        ni->ni_assocuptime = OS_GET_TICKS();

        IEEE80211_NOTE(vap, IEEE80211_MSG_ASSOC | IEEE80211_MSG_DEBUG, ni,
            "%s: station %sassociated at aid %d: %s preamble, %s slot time"
            "%s%s%s%s cap 0x%x\n"
            , __func__
            , newassoc ? "" : "re"
            , IEEE80211_NODE_AID(ni)
            , ic->ic_flags & IEEE80211_F_SHPREAMBLE ? "short" : "long"
            , ic->ic_flags & IEEE80211_F_SHSLOT ? "short" : "long"
            , ic->ic_flags & IEEE80211_F_USEPROT ? ", protection" : ""
            , ni->ni_flags & IEEE80211_NODE_QOS ? ", QoS" : ""
            , ni->ni_flags & IEEE80211_NODE_HT ? ", HT" : ""
            , ni->ni_flags & IEEE80211_NODE_HT  ? 
                       (ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40 ? "40" : "20") : ""
            , ni->ni_capinfo
        );
	 IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
			" <INFO> [Step %s - SEND %s RESP] %s: station %s at aid %d: %s preamble, %s slot time %s%s%s%s cap 0x%x\n", 
			reassoc ? "04" : "03", reassoc ? "REASSOC" : "ASSOC",
			__func__,
	            newassoc ? "associated" : "reassociated",
	            IEEE80211_NODE_AID(ni),
	            ic->ic_flags & IEEE80211_F_SHPREAMBLE ? "short" : "long",
	            ic->ic_flags & IEEE80211_F_SHSLOT ? "short" : "long",
	             ic->ic_flags & IEEE80211_F_USEPROT ? ", protection" : "",
	             ni->ni_flags & IEEE80211_NODE_QOS ? ", QoS" : "",
	            ni->ni_flags & IEEE80211_NODE_HT ? ", HT" : "",
	            ni->ni_flags & IEEE80211_NODE_HT  ? (ni->ni_htcap & IEEE80211_HTCAP_C_CHWIDTH40 ? "40" : "20") : "",
	            ni->ni_capinfo
        );

        /* give driver a chance to setup state like ni_txrate */
        if (ic->ic_newassoc != NULL)
            ic->ic_newassoc(ni, newassoc);
        /*
         * When 802.1x is not in use mark the port
         * authorized at this point so traffic can flow.
         */
        if ((ni->ni_authmode != IEEE80211_AUTH_8021X) &&
             (!RSN_AUTH_IS_SHARED_KEY(&vap->iv_rsn) || (ni->ni_authmode != IEEE80211_AUTH_SHARED)))
        {
			/*zhaoyang1 transplant from 717*/
            /*Begin:Added by duanmingzhe for thinap*/
            printk("%s node authorize\n",__func__);
            if (!thinap)
            {
                if (ni->ni_authmode != IEEE80211_AUTH_8021X)
                {
	                printk("%s node ieee80211_node_authorize\n",__func__);
                    ieee80211_node_authorize(ni);
                }
            }
            else
            {
            /*<begin:transplant by caizhibang from apv5*/
			/*yanggs add for thinap wds*/
                if(vap->vap_wds)
                {
                    
					printk("%s node ieee80211_node_authorize\n",__func__);
		            ieee80211_node_authorize(ni);
                }
				else
				{
		            printk("%s node ieee80211_node_unauthorize\n",__func__);
	                ieee80211_node_unauthorize(ni);
				}
			/*yanggs add end*/
			/*end : transplant by caizhibang from apv5>*/
            }
            /*End:Added by duanmingzhe for thinap*/
			/*zhaoyang1 transplant end*/
            //ieee80211_node_authorize(ni);
        }

        /* Update MIMO powersave flags and node rates */
        ieee80211_update_noderates(ni);

#if UMAC_SUPPORT_SMARTANTENNA
        /* Auto Smart Antenna Training when new STA associated*/
       if (ic->ic_get_smartatenna_enable(ic) && (ni->ni_flags & IEEE80211_NODE_HT)) 
       {
            if (!IEEE80211_VAP_IS_PRIVACY_ENABLED(vap) && !(ni->ni_capinfo & IEEE80211_CAPINFO_PRIVACY)) // both have no security
            {
                if (ni->is_training == 0) {
                    ni->is_training = 1;
                    ieee80211_smartantenna_start_training(ni, ic);
                }
                /* start retrain state m/c */
                if (ic->ic_smartantennaparams->retraining_enable)
                    OS_SET_TIMER(&ic->ic_smartant_retrain_timer, RETRAIN_INTERVEL); /* ms */
            }
       }
#endif
        /* need to add a station join notification */ 
    }

	/*zhaoyang1 transplant from 717*/
	 /*xiaruixin add for traffic_balance reset*/
    if (thinap && vap->iv_traffic_balance){ //Modified by zhaoyang1 for optimizing traffic balance based wlan 2013-06-19
	    wbuf_free(resp_wbuf);
	}
	 /*xiaruixin add end */
	 /*zhaoyang1 transplant end*/
}

/* 
 *  create a insfra structure network (Host AP mode).  
 */

static void ieee80211_mlme_create_infra_continue(struct ieee80211vap *vap)
{
    /* Update channel and rates of the node */
    ieee80211_node_set_chan(vap->iv_bss);
    vap->iv_cur_mode = ieee80211_chan2mode(vap->iv_bss->ni_chan);

#if UMAC_SUPPORT_BTAMP
    /*
     * For BTAMP vap, HT may be disabled based on iv_des_mode.
     *
     * TBD: Other phy properties are not controllable, such as preamble, slot, ERP,
     *      because ic is referenced to set the above properties.
     */
    if (IEEE80211_IS_CHAN_11N(vap->iv_bss->ni_chan)) {
        if (vap->iv_opmode == IEEE80211_M_BTAMP)
            vap->iv_cur_mode = vap->iv_des_mode;
    }
#endif


    /* Start host ap */
    ieee80211_vap_start(vap);
}

int 
mlme_create_infra_bss(struct ieee80211vap *vap)    
{
    struct ieee80211com         *ic = vap->iv_ic;
    struct ieee80211_channel    *chan = NULL;
    ieee80211_ssid              *ssid = NULL;
    int                         n_ssid;
    int                         error = 0;

    n_ssid = ieee80211_get_desired_ssid(vap, 0,&ssid);

    if (ssid == NULL)
        return EINVAL;
        
    /* 
     * if there is a scan in progress.
     * then there is a vap currently scanning and the chip
     * is off on a different channel. we can not bring up 
     * vap at this point.  Scan can be in progress for 
     * independant repeater vaps, since they do not change channels.
     */
    /* 
   * WAR: if ACS also in progress, then scan should be done.
   * Just in scan post event and VAP could bring up.
   */

    /*
     * When the resmgr is active, do not fail vap creation even if a scan is in progress
     */
    if (!ieee80211_resmgr_active(ic) && wlan_scan_in_progress(vap) && !wlan_autoselect_in_progress(vap)  
	&& !ieee80211_vap_vap_ind_is_set(vap)) {
        return EAGAIN;
    }

    /* create BSS node for infra network */
    error = ieee80211_create_infra_bss(vap,ssid->ssid, ssid->len);

    if (error) {
        goto err;
    }

    /*
     * at this point the bss node (vap->iv_bss) has 2 references.
     * one for the fact that it is part of the node table.
     * the second one for being a bss node and being referred from 
     * vap->iv_bss.
     */

    chan =  vap->iv_des_chan[vap->iv_des_mode];

    if (chan == NULL) {
        return EINVAL;
    }

    /*
     * issue a vap start request to resource manager.
     * if the function returns EOK (0) then its ok to change the channel synchronously
     * if the function returns EBUSY  then resource manager will 
     * switch channel asynchronously and post an event event handler registred by vap and
     * vap handler will intern call the wlan_mlme_join_infra_continue .
     */
    error = ieee80211_resmgr_vap_start(ic->ic_resmgr,vap,chan,MLME_REQ_ID,0);
    if (error == EOK) { /* no resource manager in place */
        int numvaps = ieee80211_vaps_active(ic);
        /* 
         * if there is a vap already running.
         * ignore the desired channel and use the
         * operating channel of the other vap.
         */
        /* so that cwm can do its own crap. need to untie from state */
        /* vap join is called here to wake up the chip if it is in sleep state */
        ieee80211_vap_join(vap);

        if (numvaps == 0) {
            if (error == EOK ) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Setting channel number %d\n", __func__, chan->ic_ieee);
                ieee80211_set_channel(ic, chan);
                /*Start: added by zhanghu for increasing rate*/
                mlme_handle_rate_mask_by_curmode(ic);
                /*End: added by zhanghu for increasing rate*/
                
                vap->iv_bsschan = ic->ic_curchan;	/* ieee80211 Layer - Default Configuration */
            }

            /* XXX reset erp state */
            ieee80211_reset_erp(ic, ic->ic_curmode, vap->iv_opmode);
            ieee80211_wme_initparams(vap);
        } else {
           vap->iv_bsschan = ic->ic_curchan;	/* get the current channel */
        }
        ieee80211_mlme_create_infra_continue(vap);
    }

err:
    return error;
}
void ieee80211_mlme_create_infra_continue_async(struct ieee80211vap *vap)
{
    ieee80211_mlme_create_infra_continue(vap);

    IEEE80211_DELIVER_EVENT_MLME_JOIN_COMPLETE_INFRA(vap, IEEE80211_STATUS_SUCCESS);
}

/*
 * function to handle shared auth in HOST AP mode.
 */

u_int16_t
mlme_auth_shared(struct ieee80211_node *ni, u_int16_t seq, u_int16_t status, 
                 u_int8_t *challenge,u_int16_t challenge_len)
{
	struct ieee80211vap    *vap = ni->ni_vap;
    struct ieee80211com    *ic = ni->ni_ic;
	u_int16_t              estatus = IEEE80211_STATUS_SUCCESS;

	/*
	 * NB: this can happen as we allow pre-shared key
	 * authentication to be enabled w/o wep being turned
	 * on so that configuration of these can be done
	 * in any order.  It may be better to enforce the
	 * ordering in which case this check would just be
	 * for sanity/consistency.
	 */
	estatus = 0;			/* NB: silence compiler */
	if (!IEEE80211_VAP_IS_PRIVACY_ENABLED(vap)) {
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                           ni->ni_macaddr, "%s: shared key auth %s", __func__, "PRIVACY is disabled");
		estatus = IEEE80211_STATUS_ALG;
	      IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   	" <INFO> [Step 02 - RECV AUTH] %s: shared key auth PRIVACY is disabled, estatus = ALG(%d)\n", 
		   	__func__, estatus);
	}

    if (estatus == IEEE80211_STATUS_SUCCESS) {
        switch (seq) {
        case IEEE80211_AUTH_SHARED_CHALLENGE:
        case IEEE80211_AUTH_SHARED_RESPONSE:
            if (challenge == NULL) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                                   ni->ni_macaddr, "%s: shared key auth %s\n", __func__, "no challenge");
                vap->iv_stats.is_rx_bad_auth++;
                estatus = IEEE80211_STATUS_CHALLENGE;
		   IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   		" <INFO> [Step 02 - RECV AUTH] %s: shared key auth no challenge, estatus = CHALLENGE(%d)\n", 
		   		__func__, estatus);
            } else if (challenge_len != IEEE80211_CHALLENGE_LEN) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, ni->ni_macaddr, 
                                   "%s: shared key auth bad challenge len %d", __func__, challenge_len);
                vap->iv_stats.is_rx_bad_auth++;
                estatus = IEEE80211_STATUS_CHALLENGE;
		   IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   		" <INFO> [Step 02 - RECV AUTH] %s: shared key auth bad challenge len(%d), estatus = CHALLENGE(%d)\n", 
		   		__func__, challenge_len, estatus);
            }
        default:
            break;
        }
    }

    if (estatus == IEEE80211_STATUS_SUCCESS) {
        switch (seq) {
        case IEEE80211_AUTH_SHARED_REQUEST:
            if (ni->ni_challenge == NULL)
                ni->ni_challenge = (u_int32_t *)OS_MALLOC(ic->ic_osdev ,IEEE80211_CHALLENGE_LEN,0);
            if (ni->ni_challenge == NULL) {
                IEEE80211_NOTE(ni->ni_vap,
                               IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
                               "%s: %s", __func__, "shared key challenge alloc failed");
                /* XXX statistic */
                estatus = IEEE80211_STATUS_UNSPECIFIED;
		   IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   		" <INFO> [Step 02 - RECV AUTH] %s: shared key auth challenge alloc failed, estatus = UNSPECIFIED(%d)\n", 
		   		__func__, estatus);

            } else {
                /*
                 * get random bytes for challenge text.
                 */
         
                OS_GET_RANDOM_BYTES(ni->ni_challenge,
                                    IEEE80211_CHALLENGE_LEN);
                IEEE80211_NOTE(vap,
                               IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
                               "%s: %s", __func__, "shared key auth request \n");
		   IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   		" <SEND> [Step 02 - SEND AUTH] %s: send shared key auth request frame\n", 
		   		__func__);
                ieee80211_send_auth(ni,(seq + 1),0,(u_int8_t *)ni->ni_challenge,IEEE80211_CHALLENGE_LEN);
            }
            break;
        case IEEE80211_AUTH_SHARED_RESPONSE:
            if (ni->ni_challenge == NULL) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                                   ni->ni_macaddr, "%s: shared key response %s",
                                   __func__, "no challenge recorded");
                vap->iv_stats.is_rx_bad_auth++;
                estatus = IEEE80211_STATUS_CHALLENGE;
		  IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   		" <INFO> [Step 02 - SEND AUTH] %s: shared key response no challenge recorded, estatus = CHALLENGE(%d)\n", 
		   		__func__, estatus);
            } else if (memcmp(ni->ni_challenge, challenge,
                              challenge_len) != 0) {
                IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                                   ni->ni_macaddr, "%s: shared key response %s", 
                                   __func__, "challenge mismatch");
                vap->iv_stats.is_rx_auth_fail++;
                estatus = IEEE80211_STATUS_CHALLENGE;
		  IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   		" <INFO> [Step 02 - SEND AUTH] %s: shared key response challenge mismatch, estatus = CHALLENGE(%d)\n", 
		   		__func__, estatus);
            } else {
                IEEE80211_NOTE(vap, IEEE80211_MSG_DEBUG | IEEE80211_MSG_AUTH, ni,
                               "%s: station authenticated %s\n", __func__, "shared key");
		  IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   		" <INFO> [Step 02 - SEND AUTH] %s: station authenticated shared key\n", 
		   		__func__, estatus);

		   /*zhaoyang1 transplant from 717*/
                //ieee80211_node_authorize(ni);
                /*Begin:Added by duanmingzhe for thinap*/
                if (!thinap)
                {
                    if (ni->ni_authmode != IEEE80211_AUTH_8021X)
                    {
                        printk("%s node ieee80211_node_authorize\n",__func__);
                        ieee80211_node_authorize(ni);
                    }
                }
                else
                {
                    printk("%s node ieee80211_node_unauthorize\n",__func__);
                    ieee80211_node_unauthorize(ni);
                }
                /*End:Added by duanmingzhe for thinap*/
                /*zhaoyang1 transplant end*/
                /*
                 * shared auth success.
                 */
		   IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   		" <SEND> [Step 02 - SEND AUTH] %s: send shared key auth response frame\n", 
		   		__func__);
                ieee80211_send_auth(ni,(seq + 1),0, NULL,0);
            }
            break;
        default:
            IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH,
                               ni->ni_macaddr, "%s: shared key auth bad seq %d \n", __func__, seq);
            vap->iv_stats.is_rx_bad_auth++;
            estatus = IEEE80211_STATUS_SEQUENCE;
		IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   		" <INFO> [Step 02 - SEND AUTH] %s: shared key auth bad seq(%d), estatus = SEQUENCE(%d)\n", 
		   		__func__, seq, estatus);
            break;
        }
    }

    /*
     * Send an error response.
     */
    if (estatus != IEEE80211_STATUS_SUCCESS) {
	IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   		" <SEND> [Step 02 - SEND AUTH] %s: send an error response frame, estatus = %d\n", 
		   		__func__, estatus);
        ieee80211_send_auth(ni,(seq + 1),estatus, NULL,0);
    }

    return estatus;
}

void mlme_recv_auth_ap(struct ieee80211_node *ni,
                       u_int16_t algo, u_int16_t seq, u_int16_t status_code,
                       u_int8_t *challenge, u_int8_t challenge_length, wbuf_t wbuf)
{

    struct ieee80211vap           *vap = ni->ni_vap;
    struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;
    struct ieee80211_frame        *wh;
    u_int16_t                     indication_status = IEEE80211_STATUS_SUCCESS,response_status = IEEE80211_STATUS_SUCCESS ;
    bool                          send_auth_response=true,indicate=true;;

    wh = (struct ieee80211_frame *) wbuf_header(wbuf);
    /* AP must be up and running */
    if (!mlme_priv->im_connection_up || ieee80211_vap_ready_is_clear(vap)) {
	  IEEE80211_NOTE_MAC_MGMT_DEBUG(vap, wh->i_addr2, " <FAIL> [Step 02 - RECV AUTH] %s: ap isn't up or run\n", __func__);
        return;
    }


    IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_AUTH, wh->i_addr2,
                       "%s: recv auth frame with algorithm %d seq %d \n", __func__, algo, seq);

    do {
        bool create_new_node = TRUE;

        /* Always remove the old client node. Otherwise, station count can be wrong */
        if (ni != vap->iv_bss)  {
            /* Call MLME indication handler if node is in associated state */
            if (seq == IEEE80211_AUTH_OPEN_REQUEST ||
                seq == IEEE80211_AUTH_SHARED_REQUEST) {
                IEEE80211_NOTE_MAC_MGMT_DEBUG(vap, wh->i_addr2, 
			 	" <INFO> [Step 02 - RECV AUTH] %s: station exist in same vap, delete station\n", __func__);
                ieee80211_ref_node(ni);
				/*suzhaoyu add for sta leave report*/
#if AUTELAN_SOLUTION2
				ni->ni_maintype = 1;
				ni->ni_subtype = 1;
				IEEE80211_NOTE_MAC_MGMT_DEBUG(vap, wh->i_addr2, 
				" <INFO> [Step 02 - RECV AUTH] %s: station send auth in same vap(0x%02X%04X), report delete station\n", 
				__func__, ni->ni_maintype, ni->ni_subtype);
				ieee80211_sta_leave_send_event(ni);
#endif
				/*suzhaoyu add end*/
                if(ieee80211_node_leave(ni)) {
					/*zhaoyang1 transplant from 717*/
                    //IEEE80211_DELIVER_EVENT_MLME_DISASSOC_INDICATION(vap,
                    //                                                   ni->ni_macaddr,
                    //                                                   IEEE80211_REASON_ASSOC_LEAVE);
                    /*zhaoyang1 transplant end*/
                }
                ieee80211_free_node(ni);
            } else {
                /* Second auth in AUTH_ALG_SHARED */
                create_new_node = FALSE;
            }
        }

        if (create_new_node) {
            /* create a node for the station */

            /* 
             * If the VAP is in forced paused state, then we cannot create
             * a new node because of synchronization issues. i.e. the vap is
             * in forced paused state but this new node is in unpause state.
             * But the P2P station client should not be sending packets during
             * NOA sleep anyway. So, refused this connection.
             */
            if (ieee80211_vap_is_force_paused(vap)) {
                IEEE80211_DPRINTF(vap, IEEE80211_MSG_MLME, "%s: Reject this Auth since VAP is in forced paused.\n", 
                                  __func__);
                indication_status = IEEE80211_STATUS_OTHER;
		   IEEE80211_NOTE_MAC_MGMT_DEBUG(vap, wh->i_addr2, 
		   	" <FAIL> [Step 02 - RECV AUTH] %s: reject this auth since the vap is in forced paused state, indication_status = OTHER(%d)\n", 
		   	__func__, indication_status);
                return;
            }

            ni = ieee80211_dup_bss(vap, wh->i_addr2);
            if (ni == NULL) {
                indication_status = IEEE80211_STATUS_OTHER;
		   IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   	" <FAIL> [Step 02 - RECV AUTH] %s: create a node for the station failure, indication_status = OTHER(%d)\n", 
		   	__func__, indication_status);
                return;
            }
		
            /* override bss authmode for shared auth request algorithm*/
            if (algo  == IEEE80211_AUTH_ALG_SHARED)
                ni->ni_authmode = IEEE80211_AUTH_SHARED;
        } else {
           ieee80211_ref_node(ni);
        }

        /* Validate algo */
        if (algo == IEEE80211_AUTH_ALG_SHARED && !RSN_AUTH_IS_SHARED_KEY(&vap->iv_rsn)) {
            response_status = IEEE80211_STATUS_ALG;
            indication_status = IEEE80211_STATUS_ALG;
	     IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   	" <INFO> [Step 02 - RECV AUTH] %s: response_status = ALG(%d), indication_status = ALG(%d)\n", 
		   	__func__, response_status, indication_status);
            break;
        } 

	if (algo == IEEE80211_AUTH_ALG_OPEN && RSN_AUTH_IS_SHARED_KEY(&vap->iv_rsn) && !RSN_AUTH_IS_OPEN(&vap->iv_rsn)){
            response_status = IEEE80211_STATUS_ALG;
            indication_status = IEEE80211_STATUS_ALG;
	     IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   	" <INFO> [Step 02 - RECV AUTH] %s: response_status = ALG(%d), indication_status = ALG(%d)\n", 
		   	__func__, response_status, indication_status);
            break;
        } 

        /*
         * Consult the ACL policy module if setup.
         */
        if (!ieee80211_acl_check(vap, wh->i_addr2)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_ACL,
                              "[%s]%s: auth: disallowed by ACL \n",ether_sprintf(wh->i_addr2), __func__);
            response_status = IEEE80211_STATUS_REFUSED;
            indication_status = IEEE80211_STATUS_REFUSED;
	     IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   	" <INFO> [Step 02 - RECV AUTH] %s: auth: disallowed by ACL, response_status = REFUSED(%d), indication_status = REFUSED(%d)\n", 
		   	__func__, response_status, indication_status);			
            vap->iv_stats.is_rx_acl++;
            break;
        }

        if (IEEE80211_VAP_IS_COUNTERM_ENABLED(vap)) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH | IEEE80211_MSG_CRYPTO,
                              "[%s]%s: auth: TKIP countermeasures enabled \n",ether_sprintf(wh->i_addr2), __func__);
            vap->iv_stats.is_rx_auth_countermeasures++;
            response_status = IEEE80211_REASON_MIC_FAILURE;
            indication_status = IEEE80211_STATUS_REFUSED;
	     IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   	" <INFO> [Step 02 - RECV AUTH] %s: auth: TKIP countermeasures enabled, response_status = MIC_FAILURE(%d), indication_status = REFUSED(%d)\n", 
		   	__func__, response_status, indication_status);			
            break;
        }
        /*
         * reject auth if there are too many STAs already associated.
         */
        if (vap->iv_sta_assoc >= vap->iv_max_aid) {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH,
                              "[%s]%s: num auth'd STAs is %d, max is %d, rejecting "
                              "new auth\n", ether_sprintf(wh->i_addr2), __func__,
                              vap->iv_sta_assoc, vap->iv_max_aid);

            response_status = IEEE80211_STATUS_TOOMANY;
            indication_status = IEEE80211_STATUS_TOOMANY;
	     IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   	" <INFO> [Step 02 - RECV AUTH] %s: num auth'd STAs is %d, max is %d, rejecting new auth, response_status = TOOMANY(%d), indication_status = TOOMANY(%d)\n", 
		   	__func__, vap->iv_sta_assoc, vap->iv_max_aid, response_status, indication_status);			
            break;
        }
        if (algo == IEEE80211_AUTH_ALG_OPEN) {
            if (seq != IEEE80211_AUTH_OPEN_REQUEST) {
                response_status = IEEE80211_STATUS_SEQUENCE;
                indication_status = IEEE80211_STATUS_SEQUENCE;
	         IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   	" <INFO> [Step 02 - RECV AUTH] %s: response_status = SEQUENCE(%d), indication_status = SEQUENCE(%d)\n", 
		   	__func__, response_status, indication_status);			
                break;
            }    
        } else if (algo == IEEE80211_AUTH_ALG_SHARED) {
            response_status = indication_status = mlme_auth_shared(ni,seq,status_code,challenge,challenge_length);
            send_auth_response=false;
            if (seq == IEEE80211_AUTH_SHARED_REQUEST && response_status == IEEE80211_STATUS_SUCCESS)
                indicate=false;
            break;
        } else {
            IEEE80211_DPRINTF(vap, IEEE80211_MSG_AUTH | IEEE80211_MSG_CRYPTO,
                              "[%s]%s: auth: unsupported algorithm %d \n",ether_sprintf(wh->i_addr2),algo, __func__);
            vap->iv_stats.is_rx_auth_unsupported++;
            response_status = IEEE80211_STATUS_ALG;
            indication_status = IEEE80211_STATUS_ALG;
	      IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
		   	" <INFO> [Step 02 - RECV AUTH] %s: auth: unsupported algorithm(%d), response_status = ALG(%d), indication_status = ALG(%d)\n", 
		   	__func__, algo, response_status, indication_status);			
            break;
        }
    } while (FALSE);

    if (indicate ) {

        IEEE80211_DELIVER_EVENT_MLME_AUTH_INDICATION(vap, ni->ni_macaddr, indication_status);
    }

    if (send_auth_response) {
	  IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
	  	" <SEND> [Step 02 - SEND AUTH] %s: send auth frame, response_status = %d\n", 
	  	__func__, response_status);
        ieee80211_send_auth(ni, seq + 1, response_status, NULL, 0);
    }

    IEEE80211_DELETE_NODE_TARGET(ni, ni->ni_ic, vap, 0);
    if (indication_status != IEEE80211_STATUS_SUCCESS ){
	IEEE80211_NOTE_MGMT_DEBUG(vap, ni, 
	  	" <INFO> [Step 02 - RECV AUTH] %s: auth is not success, remove the node from node table, indication_status = %d\n", 
	  	__func__, indication_status);
        /* auth is not success, remove the node from node table*/
        ieee80211_node_leave(ni);
    }
    /*
     * release the reference created at the begining of the case above
     * either by alloc_node or ref_node.
     */ 
    ieee80211_free_node(ni);
}

void
ieee80211_mlme_node_leave_ap(struct ieee80211_node *ni)
{
    struct ieee80211vap         *vap = ni->ni_vap;
    struct ieee80211_mlme_priv  *mlme_priv = vap->iv_mlme_priv;
    ieee80211_mlme_event          event;

    ASSERT(vap != NULL);
    ASSERT(vap->iv_opmode != IEEE80211_M_STA);

    event.u.event_sta.sta_count= vap->iv_sta_assoc;
    event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
    event.u.event_sta.ni = ni;

    event.type = IEEE80211_MLME_EVENT_STA_LEAVE;
    ieee80211_mlme_deliver_event(mlme_priv,&event);

    /* NB: preserve ni_table */
    if (ieee80211node_has_flag(ni, IEEE80211_NODE_PWR_MGT)) {

        vap->iv_ps_sta--;
        ieee80211node_clear_flag(ni, IEEE80211_NODE_PWR_MGT);
#if NOT_YET
        if (ieee80211node_has_flag(ni, IEEE80211_NODE_UAPSD_TRIG)) {
            ieee80211node_clear_flag(ni, IEEE80211_NODE_UAPSD_TRIG);
            IEEE80211_UAPSD_LOCK(ni->ni_ic);
            ni->ni_ic->ic_uapsdmaxtriggers--;
            IEEE80211_UAPSD_UNLOCK(ni->ni_ic);
        }
#endif
    
        event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
        event.type = IEEE80211_MLME_EVENT_STA_EXIT_PS;
        ieee80211_mlme_deliver_event(mlme_priv,&event);
    }


}

/* Begin:Add by chenxf for powersave performance 2014-06-05 */

/*
 * chenxf add for powersave perf
 * since there's sth wrong when we move function 'ieee80211_mlme_node_pwrsave_ap' to interrupt context 'ath_rx_intr'
 * the error happens occasionally, because of flushing the PS queue when ni exit PS mode in interrupt context.
 *
 * solution: split function 'ieee80211_mlme_node_pwrsave_ap' into two subfunctions
 * one is 'ieee80211_mlme_node_enter_pwrsave_ap' will be called in interrupt context, in charge of setting enter PS mode flag ASAP
 * the other is 'ieee80211_mlme_node_exit_pwrsave_ap' remains the same original place, need times to flush PS queue
 */

void
ieee80211_mlme_node_enter_pwrsave_ap(struct ieee80211_node *ni, int enable)
{
    struct ieee80211vap *vap = ni->ni_vap;
    ieee80211_mlme_event          event;

    if  ( ((ni->ni_flags & IEEE80211_NODE_PWR_MGT) != 0) ^ enable) {
        struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

        if (enable) {
            vap->iv_ps_sta++;
            ni->ni_flags |= IEEE80211_NODE_PWR_MGT;
            IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
                           "%s: power save mode on, %u sta's in ps mode\n", __func__, vap->iv_ps_sta);
            ieee80211node_pause(ni);
            event.type = IEEE80211_MLME_EVENT_STA_ENTER_PS;
        }
		
        event.u.event_sta.sta_count= vap->iv_sta_assoc;
        event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
        event.u.event_sta.ni = ni;
        ieee80211_mlme_deliver_event(mlme_priv,&event);
    }
}

void
ieee80211_mlme_node_exit_pwrsave_ap(struct ieee80211_node *ni, int enable)
{
    struct ieee80211vap *vap = ni->ni_vap;
    ieee80211_mlme_event          event;

    if  ( ((ni->ni_flags & IEEE80211_NODE_PWR_MGT) != 0) ^ enable) {
        struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

        if (0 == enable) {
            vap->iv_ps_sta--;
            ni->ni_flags &= ~IEEE80211_NODE_PWR_MGT;
            ieee80211node_unpause(ni);
            IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
                           "%s: power save mode off, %u sta's in ps mode\n", __func__, vap->iv_ps_sta);
            event.type = IEEE80211_MLME_EVENT_STA_EXIT_PS;

        }

        event.u.event_sta.sta_count= vap->iv_sta_assoc;
        event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
        event.u.event_sta.ni = ni;
        ieee80211_mlme_deliver_event(mlme_priv,&event);
    }
}

/* End:Add by chenxf for powersave performance 2014-06-05 */

void
ieee80211_mlme_node_pwrsave_ap(struct ieee80211_node *ni, int enable)
{
    struct ieee80211vap *vap = ni->ni_vap;
    ieee80211_mlme_event          event;

    if  ( ((ni->ni_flags & IEEE80211_NODE_PWR_MGT) != 0) ^ enable) {
        struct ieee80211_mlme_priv    *mlme_priv = vap->iv_mlme_priv;

        if (enable) {
            vap->iv_ps_sta++;
            ni->ni_flags |= IEEE80211_NODE_PWR_MGT;
            IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
                           "%s: power save mode on, %u sta's in ps mode\n", __func__, vap->iv_ps_sta);
            ieee80211node_pause(ni);
            event.type = IEEE80211_MLME_EVENT_STA_ENTER_PS;
        } else {

            vap->iv_ps_sta--;
            ni->ni_flags &= ~IEEE80211_NODE_PWR_MGT;
            ieee80211node_unpause(ni);
            IEEE80211_NOTE(vap, IEEE80211_MSG_POWER, ni,
                           "%s: power save mode off, %u sta's in ps mode\n", __func__, vap->iv_ps_sta);
            event.type = IEEE80211_MLME_EVENT_STA_EXIT_PS;

        }

        event.u.event_sta.sta_count= vap->iv_sta_assoc;
        event.u.event_sta.sta_ps_count= vap->iv_ps_sta;
        event.u.event_sta.ni = ni;
        ieee80211_mlme_deliver_event(mlme_priv,&event);
    }
}


#endif /* UMAC_SUPPORT_AP */
