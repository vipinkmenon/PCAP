#include "pcap.h"
#include "sdCard.h"



int initPCAP(u32 DEVICE_ID,XDcfg *DcfgInstance){
	int Status;
	XDcfg_Config *ConfigPtr;
	ConfigPtr = XDcfg_LookupConfig(DEVICE_ID);
	Status = XDcfg_CfgInitialize(DcfgInstance, ConfigPtr,ConfigPtr->BaseAddr);
	//XDcfg_SetLockRegister(&DcfgInstance, 0x757BDF0D);
	if (Status != XST_SUCCESS) {
		xil_printf("PCAP init failed\n\r");
		return XST_FAILURE;
	}
	Status = Xil_In32(SLCR_PCAP_CLK_CTRL);
	if (!(Status & SLCR_PCAP_CLK_CTRL_EN_MASK)) {
		Xil_Out32(SLCR_UNLOCK, SLCR_UNLOCK_VAL);
		Xil_Out32(SLCR_PCAP_CLK_CTRL,(Status | SLCR_PCAP_CLK_CTRL_EN_MASK));
		Xil_Out32(SLCR_UNLOCK, SLCR_LOCK_VAL);
	}
	return XST_SUCCESS;
}


int partialReconfigure(char *filename,XDcfg *DcfgInstance,char *bitStreamBuffer){
	int Status;
	u32 bitStreamSize;
	Status = ReadFile(filename,(u32)bitStreamBuffer);
	if (Status == XST_FAILURE) {
		print("file read failed!!\n\r");
		return XST_FAILURE;
	}
	XDcfg_IntrClear(DcfgInstance, XDCFG_IXR_D_P_DONE_MASK|XDCFG_IXR_DMA_DONE_MASK);
	bitStreamSize = Status/4;
	Status = XDcfg_Transfer(DcfgInstance, (u8 *)bitStreamBuffer,bitStreamSize,(u8 *)XDCFG_DMA_INVALID_ADDRESS,0, XDCFG_NON_SECURE_PCAP_WRITE);
	if (Status != XST_SUCCESS) {
		xil_printf("PR failed\n\r");
		return XST_FAILURE;
	}
	Status = XDcfg_IntrGetStatus(DcfgInstance);
	while ((Status & XDCFG_IXR_DMA_DONE_MASK) != XDCFG_IXR_DMA_DONE_MASK)
	{
		Status = XDcfg_IntrGetStatus(DcfgInstance);
	}
	Status = XDcfg_IntrGetStatus(DcfgInstance);
	while ((Status & XDCFG_IXR_D_P_DONE_MASK) != XDCFG_IXR_D_P_DONE_MASK)
	{
		Status = XDcfg_IntrGetStatus(DcfgInstance);
	}
	return XST_SUCCESS;
}


int fullReconfigure(char *filename,XDcfg *DcfgInstance,char *bitStreamBuffer){
	int Status;
	u32 bitStreamSize;
	int *addr;
	Status = ReadFile(filename,(u32)bitStreamBuffer);
	if (Status == XST_FAILURE) {
		print("file read failed!!\n\r");
		return XST_FAILURE;
	}
	bitStreamSize = Status/4;
	Status = ClearPcapStatus(DcfgInstance);
	if (Status != XST_SUCCESS) {
		xil_printf("PCAP_CLEAR_STATUS_FAIL \r\n");
		return XST_FAILURE;
	}
	FabricInit(DcfgInstance);
	Status = XDcfg_Transfer(DcfgInstance, (u8 *)bitStreamBuffer,bitStreamSize,(u8 *)XDCFG_DMA_INVALID_ADDRESS,0, XDCFG_NON_SECURE_PCAP_WRITE);
	if (Status != XST_SUCCESS) {
		xil_printf("Status of XDcfg_Transfer = %d \r \n",Status);
		return XST_FAILURE;
	}
	Status = XDcfgPollDone(DcfgInstance,XDCFG_IXR_DMA_DONE_MASK, MAX_COUNT);
	if (Status != XST_SUCCESS) {
		xil_printf("PCAP_DMA_DONE_FAIL \r\n");
		return XST_FAILURE;
	}
	if (Status != XST_SUCCESS) {
		xil_printf("PCAP_DMA_DONE_FAIL \r\n");
		return XST_FAILURE;
	}

	Status = XDcfg_IntrGetStatus(DcfgInstance);
	if (Status & FSBL_XDCFG_IXR_ERROR_FLAGS_MASK) {
		xil_printf("Errors in PCAP \r\n");
		return XST_FAILURE;
	}
	return XST_SUCCESS;
}



/******************************************************************************/
/**
*
* This function programs the Fabric for use.
*
* @param	None
*
* @return	None
*		- XST_SUCCESS if the Fabric  initialization is successful
*		- XST_FAILURE if the Fabric  initialization fails
* @note		None
*
****************************************************************************/
void FabricInit(XDcfg *DcfgInstance)
{
	u32 PcapReg;
	u32 PcapCtrlRegVal;
	u32 StatusReg;

	/*
	 * Set Level Shifters DT618760 - PS to PL enabling
	 */
	Xil_Out32(PS_LVL_SHFTR_EN, LVL_PS_PL);
	//xil_printf("Level Shifter Value = 0x%x \r\n",Xil_In32(PS_LVL_SHFTR_EN));

	/*
	 * Get DEVCFG controller settings
	 */
	PcapReg = XDcfg_ReadReg(DcfgInstance->Config.BaseAddr,
				XDCFG_CTRL_OFFSET);

	/*
	 * Setting PCFG_PROG_B signal to high
	 */
	XDcfg_WriteReg(DcfgInstance->Config.BaseAddr, XDCFG_CTRL_OFFSET,
				(PcapReg | XDCFG_CTRL_PCFG_PROG_B_MASK));

	/*
	 * Check for AES source key
	 */
	PcapCtrlRegVal = XDcfg_GetControlRegister(DcfgInstance);
	if (PcapCtrlRegVal & XDCFG_CTRL_PCFG_AES_FUSE_MASK) {
		/*
		 * 5msec delay
		 */
		usleep(5000);
	}

	/*
	 * Setting PCFG_PROG_B signal to low
	 */
	XDcfg_WriteReg(DcfgInstance->Config.BaseAddr, XDCFG_CTRL_OFFSET,
				(PcapReg & ~XDCFG_CTRL_PCFG_PROG_B_MASK));

	/*
	 * Check for AES source key
	 */
	if (PcapCtrlRegVal & XDCFG_CTRL_PCFG_AES_FUSE_MASK) {
		/*
		 * 5msec delay
		 */
		usleep(5000);
	}

	/*
	 * Polling the PCAP_INIT status for Reset
	 */
	while(XDcfg_GetStatusRegister(DcfgInstance) &
				XDCFG_STATUS_PCFG_INIT_MASK);

	/*
	 * Setting PCFG_PROG_B signal to high
	 */
	XDcfg_WriteReg(DcfgInstance->Config.BaseAddr, XDCFG_CTRL_OFFSET,
			(PcapReg | XDCFG_CTRL_PCFG_PROG_B_MASK));

	/*
	 * Polling the PCAP_INIT status for Set
	 */
	while(!(XDcfg_GetStatusRegister(DcfgInstance) &
			XDCFG_STATUS_PCFG_INIT_MASK));

	/*
	 * Get Device configuration status
	 */
	StatusReg = XDcfg_GetStatusRegister(DcfgInstance);
	//xil_printf("Devcfg Status register = 0x%x \r\n",StatusReg);

	//xil_printf("PCAP:Fabric is Initialized done\r\n");
}

u32 ClearPcapStatus(XDcfg *DcfgInstPtr)
{

	u32 StatusReg;
	u32 IntStatusReg;

	/*
	 * Clear it all, so if Boot ROM comes back, it can proceed
	 */
	XDcfg_IntrClear(DcfgInstPtr, 0xFFFFFFFF);

	/*
	 * Get PCAP Interrupt Status Register
	 */
	IntStatusReg = XDcfg_IntrGetStatus(DcfgInstPtr);
	if (IntStatusReg & FSBL_XDCFG_IXR_ERROR_FLAGS_MASK) {
		xil_printf("FATAL errors in PCAP %x\r\n",
				IntStatusReg);
		return XST_FAILURE;
	}

	/*
	 * Read the PCAP status register for DMA status
	 */
	StatusReg = XDcfg_GetStatusRegister(DcfgInstPtr);

	//xil_printf("PCAP:StatusReg = 0x%.8x\r\n", StatusReg);

	/*
	 * If the queue is full, return w/ XST_DEVICE_BUSY
	 */
	if ((StatusReg & XDCFG_STATUS_DMA_CMD_Q_F_MASK) ==
			XDCFG_STATUS_DMA_CMD_Q_F_MASK) {

		xil_printf("PCAP_DEVICE_BUSY\r\n");
		return XST_DEVICE_BUSY;
	}

	//xil_printf("PCAP:device ready\r\n");

	/*
	 * There are unacknowledged DMA commands outstanding
	 */
	if ((StatusReg & XDCFG_STATUS_DMA_CMD_Q_E_MASK) !=
			XDCFG_STATUS_DMA_CMD_Q_E_MASK) {

		IntStatusReg = XDcfg_IntrGetStatus(DcfgInstPtr);

		if ((IntStatusReg & XDCFG_IXR_DMA_DONE_MASK) !=
				XDCFG_IXR_DMA_DONE_MASK){
			/*
			 * Error state, transfer cannot occur
			 */
			xil_printf("PCAP:IntStatus indicates error\r\n");
			return XST_FAILURE;
		}
		else {
			/*
			 * clear out the status
			 */
			XDcfg_IntrClear(DcfgInstPtr, XDCFG_IXR_DMA_DONE_MASK);
		}
	}

	if ((StatusReg & XDCFG_STATUS_DMA_DONE_CNT_MASK) != 0) {
		XDcfg_IntrClear(DcfgInstPtr, StatusReg &
				XDCFG_STATUS_DMA_DONE_CNT_MASK);
	}

	//xil_printf("PCAP:Clear done\r\n");

	return XST_SUCCESS;
}


int XDcfgPollDone(XDcfg *DcfgInstPtr,u32 MaskValue, u32 MaxCount)
{
	int Count = MaxCount;
	u32 IntrStsReg = 0;

	/*
	 * poll for the DMA done
	 */
	IntrStsReg = XDcfg_IntrGetStatus(DcfgInstPtr);
	while ((IntrStsReg & MaskValue) !=
				MaskValue) {
		IntrStsReg = XDcfg_IntrGetStatus(DcfgInstPtr);
		Count -=1;

		if (IntrStsReg & FSBL_XDCFG_IXR_ERROR_FLAGS_MASK) {
				xil_printf("FATAL errors in PCAP %x\r\n",
						IntrStsReg);
				//PcapDumpRegisters();
				return XST_FAILURE;
		}

		if(!Count) {
			xil_printf("PCAP transfer timed out \r\n");
			return XST_FAILURE;
		}
		/*if (Count > (MAX_COUNT-100)) {
			xil_printf(".");
		}*/
	}

	//xil_printf("\n\r");

	XDcfg_IntrClear(DcfgInstPtr, IntrStsReg & MaskValue);

	return XST_SUCCESS;
}
