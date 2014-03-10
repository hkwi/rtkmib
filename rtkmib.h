#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#define __PACK__		__attribute__((packed))

#define MIB_ERR_GENERIC		-1
#define MIB_ERR_COMPRESSED	-2


#define FLASH_DEVICE_NAME	"/dev/mtdblock0"
#define MIB_OFFSET_DEFAULT	0x6000
#define MIB_WLAN_OFFSET		13

#ifdef RTK_HW_OFFSET
#define MIB_OFFSET		RTK_HW_OFFSET
#else
#define MIB_OFFSET		MIB_OFFSET_DEFAULT
#endif

#define HW_SETTING_VER		3 /* hw setting version */

#define MIB_HEADER_TAG		"H6"
#define MIB_TAG_LEN		2
#define MIB_SIG_LEN		4
typedef struct mib_hdr
{
	unsigned char  sig[ MIB_SIG_LEN ]; /* tag + version */
	unsigned short len;
} __PACK__ mib_hdr_t;

#define MIB_HEADER_COMP_TAG	"COMP"
#define MIB_HEADER_COMPHS_TAG	"HS"
#define MIB_HEADER_COMPCS_TAG	"CS"
#define MIB_COMPR_TAG_LEN	4
#define MIB_COMPR_SIG_LEN	6
typedef struct mib_hdr_compr
{
	unsigned char sig[ MIB_COMPR_SIG_LEN ]; /* tag + type */
	uint16_t factor;
	uint32_t len;
} __PACK__ mib_hdr_compr_t;

#ifdef HAVE_RTK_DUAL_BAND_SUPPORT
#define NUM_WLAN_INTERFACE		2
#else
#define NUM_WLAN_INTERFACE		1
#endif

#define MAX_2G_CHANNEL_NUM_MIB		14
#define MAX_5G_CHANNEL_NUM_MIB		196
#define MAX_5G_DIFF_NUM			14

typedef struct mib_wlan
{
	unsigned char macAddr[6];
	unsigned char macAddr1[6];
	unsigned char macAddr2[6];
	unsigned char macAddr3[6];
	unsigned char macAddr4[6];
	unsigned char macAddr5[6];
	unsigned char macAddr6[6];
	unsigned char macAddr7[6];
	unsigned char pwrlevelCCK_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrlevelCCK_B[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrlevelHT40_1S_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrlevelHT40_1S_B[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiffHT40_2S[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiffHT20[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiffOFDM[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char regDomain;
	unsigned char rfType;
	unsigned char ledType; /* LED type, see LED_TYPE_T for definition */
	unsigned char xCap;
	unsigned char TSSI1;
	unsigned char TSSI2;
	unsigned char Ther;
	unsigned char trswitch;
	unsigned char trswpape_c9;
	unsigned char trswpape_cc;
	unsigned char target_pwr;
	unsigned char Reserved5;
	unsigned char Reserved6;
	unsigned char Reserved7;
	unsigned char Reserved8;
	unsigned char Reserved9;
	unsigned char Reserved10;
	unsigned char pwrlevel5GHT40_1S_A[ MAX_5G_CHANNEL_NUM_MIB ];
	unsigned char pwrlevel5GHT40_1S_B[ MAX_5G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff5GHT40_2S[ MAX_5G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff5GHT20[ MAX_5G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff5GOFDM[ MAX_5G_CHANNEL_NUM_MIB ];

#define PIN_LEN 8
	unsigned char wscPin[ PIN_LEN + 1 ];

#ifdef HAVE_RTK_AC_SUPPORT
	unsigned char pwrdiff_20BW1S_OFDM1T_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_40BW2S_20BW2S_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_OFDM2T_CCK2T_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_40BW3S_20BW3S_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_4OFDM3T_CCK3T_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_40BW4S_20BW4S_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_OFDM4T_CCK4T_A[ MAX_2G_CHANNEL_NUM_MIB ];

	unsigned char pwrdiff_5G_20BW1S_OFDM1T_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_40BW2S_20BW2S_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_40BW3S_20BW3S_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_40BW4S_20BW4S_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_RSVD_OFDM4T_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW1S_160BW1S_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW2S_160BW2S_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW3S_160BW3S_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW4S_160BW4S_A[ MAX_5G_DIFF_NUM ];

	unsigned char pwrdiff_20BW1S_OFDM1T_B[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_40BW2S_20BW2S_B[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_OFDM2T_CCK2T_B[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_40BW3S_20BW3S_B[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_OFDM3T_CCK3T_B[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_40BW4S_20BW4S_B[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_OFDM4T_CCK4T_B[ MAX_2G_CHANNEL_NUM_MIB ];

	unsigned char pwrdiff_5G_20BW1S_OFDM1T_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_40BW2S_20BW2S_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_40BW3S_20BW3S_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_40BW4S_20BW4S_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_RSVD_OFDM4T_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW1S_160BW1S_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW2S_160BW2S_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW3S_160BW3S_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW4S_160BW4S_B[ MAX_5G_DIFF_NUM ];
#endif
} __PACK__ mib_wlan_t;

typedef struct mib_wlan_ac
{
	unsigned char pwrdiff_20BW1S_OFDM1T_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_40BW2S_20BW2S_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_OFDM2T_CCK2T_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_40BW3S_20BW3S_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_4OFDM3T_CCK3T_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_40BW4S_20BW4S_A[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_OFDM4T_CCK4T_A[ MAX_2G_CHANNEL_NUM_MIB ];

	unsigned char pwrdiff_5G_20BW1S_OFDM1T_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_40BW2S_20BW2S_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_40BW3S_20BW3S_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_40BW4S_20BW4S_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_RSVD_OFDM4T_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW1S_160BW1S_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW2S_160BW2S_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW3S_160BW3S_A[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW4S_160BW4S_A[ MAX_5G_DIFF_NUM ];

	unsigned char pwrdiff_20BW1S_OFDM1T_B[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_40BW3S_20BW3S_B[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_OFDM3T_CCK3T_B[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_40BW4S_20BW4S_B[ MAX_2G_CHANNEL_NUM_MIB ];
	unsigned char pwrdiff_OFDM4T_CCK4T_B[ MAX_2G_CHANNEL_NUM_MIB ];

	unsigned char pwrdiff_5G_20BW1S_OFDM1T_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_40BW2S_20BW2S_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_40BW3S_20BW3S_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_40BW4S_20BW4S_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_RSVD_OFDM4T_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW1S_160BW1S_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW2S_160BW2S_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW3S_160BW3S_B[ MAX_5G_DIFF_NUM ];
	unsigned char pwrdiff_5G_80BW4S_160BW4S_B[ MAX_5G_DIFF_NUM ];
} __PACK__ mib_wlan_ac_t;

typedef struct mib
{
	unsigned char board_ver;
	unsigned char nic0_addr[6];
	unsigned char nic1_addr[6];
	mib_wlan_t wlan[ NUM_WLAN_INTERFACE ];
} __PACK__ mib_t;
