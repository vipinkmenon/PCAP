/*
 * pcap.h
 *
 *  Created on: May 18, 2020
 *      Author: VIPIN
 */

#ifndef SRC_PCAP_H_
#define SRC_PCAP_H_

#include "xdevcfg.h"
#include "xil_types.h"

#define SLCR_PCAP_CLK_CTRL XPAR_PS7_SLCR_0_S_AXI_BASEADDR + 0x168 /**< SLCR
					* PCAP clock control register address
					*/
#define MAX_COUNT 1000000000
#define SLCR_PCAP_CLK_CTRL_EN_MASK 0x1

#define SLCR_LOCK	0xF8000004
#define SLCR_LOCK_VAL	0x767B
#define SLCR_UNLOCK_VAL	0xDF0D
#define SLCR_UNLOCK	0xF8000008 /**< SLCR Write Protection Unlock */
#define SLCR_LVL_SHFTR_EN 0xF8000900 /**< SLCR Level Shifters Enable */

#define PS_LVL_SHFTR_EN	(XPS_SYS_CTRL_BASEADDR + 0x900)
#define LVL_PS_PL 0x0000000A

#define FSBL_XDCFG_IXR_ERROR_FLAGS_MASK		(XDCFG_IXR_AXI_WERR_MASK | \
						XDCFG_IXR_AXI_RTO_MASK |  \
						XDCFG_IXR_AXI_RERR_MASK | \
						XDCFG_IXR_RX_FIFO_OV_MASK | \
						XDCFG_IXR_DMA_CMD_ERR_MASK |\
						XDCFG_IXR_DMA_Q_OV_MASK |   \
						XDCFG_IXR_P2D_LEN_ERR_MASK |\
						XDCFG_IXR_PCFG_HMAC_ERR_MASK)

void FabricInit(XDcfg *DcfgInstance);
int initPCAP(u32 DEVICE_ID,XDcfg *DcfgInstance);
int fullReconfigure(char *filename,XDcfg *DcfgInstance,char *bitStreamBuffer);
int partialReconfigure(char *filename,XDcfg *DcfgInstance,char *bitStreamBuffer);
u32 ClearPcapStatus(XDcfg *DcfgInstPtr);
int XDcfgPollDone(XDcfg *DcfgInstPtr,u32 MaskValue, u32 MaxCount);
#endif /* SRC_PCAP_H_ */
