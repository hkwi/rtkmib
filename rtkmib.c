#include <getopt.h>
#include <stdarg.h>

#include "rtkmib.h"
#include "mibtbl.h"

#define NAME		"rtkmib"
#define VERSION		"0.0.3"


uint8_t verbose = 0;
static const char *opt_string = ":g:i:O:o:hv";
static struct option long_options[] = {
	{ "get", required_argument, NULL, 'g' },
	{ "input", required_argument, NULL, 'i' },
	{ "output", required_argument, NULL, 'O' },
	{ "offset", required_argument, NULL, 'o' },
	{ "help", no_argument, NULL, 'h' },
	{ "verbose", no_argument, NULL, 'v' },
	{ 0, 0, 0, 0 },
};

void usage ( char *pname ) {
	char **dp;
	char *optdoc[] = {
		"\n",
		"   Options:\n",
		"   -g, --get              get a part of MIB information:\n",
		"                          ver, macs, mac0, mac1, wmac0, wcal\n",
		"                          default: ver\n",
		"   -i, --input            input file name\n",
		"   -O, --output           output file name\n",
		"   -o, --offset           MIB data start offset (bytes)\n",
		"   -h, --help             print this help message\n",
		"   -v, --verbose          see what's going on under the cap\n",
		"\n",
		"If you find bugs, cockroaches or other nasty insects don't\n",
		"send them to roman@advem.lv - just kill 'em! ;)\n",
		"\n",
		0
	};
	printf( "\n%s v%s\n", NAME, VERSION );
	printf( "Usage: %s [OPTIONS]\n", pname );
	for (dp = optdoc; *dp; dp++) {
		printf( "%s", *dp );
	}
}

static void printv( const char *format, ... )
{
	if ( !format )
		return;

	if ( verbose ) {
		va_list args;
		va_start( args, format );
		vprintf( format, args );
		va_end( args );
	}
}

inline int is_big_endian( void )
{
	union {
		uint32_t i;
		char c[4];
	} e = { 0x01000000 };

	return e.c[0];
}

inline uint16_t swap16( uint16_t x )
{
	return is_big_endian()? x : ((x >> 8) & 0xff) | (x << 8);
}

inline uint32_t swap32( uint32_t x )
{
	return is_big_endian()? x :
				(x >> 24) |
				((x << 8) & 0x00ff0000) |
				((x >> 8) & 0x0000ff00) |
				(x << 24);
}

static void print_hex( unsigned char *buf, uint32_t size )
{
	if ( !buf ) {
		printf( "Invalid buffer pointer!\n" );
		return;
	}

	uint32_t pos = 0;
	uint32_t lines = 0;

	while ( pos < size ) {
		printf(" %02x", buf[pos]);
		pos++;
		if ( lines == 31 ) {
			printf("\n");
			lines = 0;
			continue;
		}
		if ( lines == 7 || lines == 15 || lines == 23 )
			printf("  ");
		lines++;
	}
	printf("\n");
}

static void print_mac( unsigned char *buf )
{
	if ( !buf )
		return;

	printf( "%02x:%02x:%02x:%02x:%02x:%02x",
			buf[0], buf[1], buf[2],
			buf[3], buf[4], buf[5] );
}

static int flash_read( char *mtd, int offset, int len, char *buf )
{
	if ( !buf || !mtd || len < 0 )
		return -1;

	int err = 0;
	int fd = open( mtd, O_RDONLY );

	if ( fd < 0 ) {
		printv( "Flash read error: %m\n" );
		return fd;
	}

	if ( offset > 0 )
		lseek( fd, offset, SEEK_SET );

	if ( read( fd, buf, len ) != len )
		err = -1;

	close( fd );

	return err;
}

static int mib_read( char *mtd, unsigned int offset,
			unsigned char **mib, uint32_t *size )
{
	*mib = NULL;
	mib_hdr_t header;
	mib_hdr_compr_t header_compr;
	unsigned int len = 0;
	int compression = 0;
	unsigned char *sig = NULL;

	if ( flash_read( mtd, offset,
			 sizeof(mib_hdr_t), (char *)&header ) )
	{
		printv( "probe header failed\n" );
		return MIB_ERR_GENERIC;
	}

	if ( !memcmp( MIB_HEADER_COMP_TAG,
		      header.sig,
		      MIB_COMPR_TAG_LEN ) )
	{

		printv( "MIB is compressed!\n" );

		if ( flash_read( mtd, offset, sizeof(mib_hdr_compr_t),
						(char *)&header_compr ) )
		{
			printv( "read header failed\n" );
			return MIB_ERR_GENERIC;
		}
		sig = header_compr.sig;
		len = swap32(header_compr.len);
		compression = swap16(header_compr.factor);
	} else {
		sig = header.sig;
		len = swap16(header.len);
	}

	printv( "Header info:\n" );
	if ( compression ) {
		printv( "  signature: '%.6s'\n", sig );
		printv( "  compression factor: 0x%x\n", compression );
	} else {
		printv( "  signature: '%.2s'\n", sig );
	}
	printv( "  data size: 0x%x\n", len );

	*mib = (unsigned char *)malloc(len);

	if ( compression ) {
		*size = len;
		if ( flash_read( mtd, offset + sizeof(mib_hdr_compr_t),
				 len, (char *)*mib ) )
		{
			printv( "MIB read failed\n" );
			return MIB_ERR_GENERIC;
		}
		return MIB_ERR_COMPRESSED;
	}

	if ( flash_read( mtd, offset + sizeof(mib_hdr_t),
			 len, (char *)*mib ) )
	{
		printv( "MIB read failed\n" );
		return MIB_ERR_GENERIC;
	}

	return len;
}

#define RING_SIZE       4096    /* size of ring buffer, must be power of 2 */
#define UL_MATCH        18      /* upper limit for match_length */
#define THRESHOLD       2       /* encode string into position and length
                                 * if match_length is greater than this */
static int mib_decode( unsigned char *in, uint32_t len, unsigned char **out )
{
	if ( !in || !out || len < 1 )
		return -1;

	int  i, j, k, c;
	int r = RING_SIZE - UL_MATCH;
	unsigned int flags = 0;
	unsigned int pos = 0;
	unsigned int explen = 0;

	unsigned char *text_buf =
			(unsigned char *)malloc( RING_SIZE + UL_MATCH - 1 );
	if ( !text_buf )
		return -1;

	*out = (unsigned char *)malloc( len );
	if ( !*out ) {
		free(text_buf);
		return -1;
	}

	/* original code initializes text_buf with spaces */
	memset( text_buf, ' ', r );
	memset( *out, 0, len );

	while (1) {
		if ( ((flags >>= 1) & 0x100) == 0 ) {
			if ( pos++ > len )
				break;
			c = *in++;		/* get flags for frame */
			flags = c | 0xff00;	/* uses higher byte cleverly */
		}				/* to count eight */
		/* test next flag bit */
		if ( flags & 1 ) {
			/* flag bit of 1 means unencoded byte */
			if ( pos++ > len )
				break;
			c = *in++;
			if ( explen + 1 > len )
				*out = (unsigned char *)realloc( *out, explen + 1 );
			(*out)[ explen ] = c;	/* copy to output */
			//printf("%i: %x\n", explen, c); fflush(stdout);
			explen++;
			text_buf[ r ] = c;	/* and to text_buf */
			r++;
			r &= (RING_SIZE - 1);
		} else {
			/* 0 means encoded info */
			if ( pos++ > len )
				break;
			i = *in++;		/* get position */
			if ( pos++ > len )
				break;
			j = *in++;		/* get length of run */

			i |= ((j & 0xf0) << 4);	    /* i is now offset of run */
			j = (j & 0x0f) + THRESHOLD; /* j is the length */

			for ( k = 0; k <= j; k++ ) {
				c = text_buf[ (i + k) & (RING_SIZE - 1) ];
				if ( explen + 1 > len )
					*out = (unsigned char *)realloc( (void *)*out, explen + 1 );
				(*out)[ explen ] = c;
				//printf("c%i: %x\n", explen, c); fflush(stdout);
				explen++;
				text_buf[ r ] = c;
				r++;
				r &= (RING_SIZE - 1);
			}
		}
	}

	free(text_buf);
	return explen;
}

static void mibtbl_to_struct( unsigned char *tbl,
			      uint32_t size,
			      unsigned char *mib )
{
	if ( !tbl || ! mib )
		return;

	int i = 0;
	mibtbl_t mibtbl;

	while ( i < size ) {
		memcpy( &mibtbl, tbl + i, sizeof(mibtbl_t) );
		i += sizeof(mibtbl_t);

		/* does 0xc900 mean the end of a table? */
		if( swap16(mibtbl.type) > MIB_TABLE_LIST ) {
			printv( "Next table with size 0x%02x!\n",
						swap16(mibtbl.size) );
			continue;
		}

		switch ( swap16(mibtbl.type) ) {
		case 0:
			printv("End of MIB tables!\n");
			break;
		case MIB_HW_BOARD_VER:
			memcpy( &(((mib_t *)mib)->board_ver),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_NIC0_ADDR:
			memcpy( &(((mib_t *)mib)->nic0_addr),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_NIC1_ADDR:
			memcpy( &(((mib_t *)mib)->nic1_addr),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_WLAN_ADDR:
			memcpy( &(((mib_t *)mib)->wlan->macAddr),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_REG_DOMAIN:
			memcpy( &(((mib_t *)mib)->wlan->regDomain),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_RF_TYPE:
			memcpy( &(((mib_t *)mib)->wlan->rfType),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_LED_TYPE:
			memcpy( &(((mib_t *)mib)->wlan->ledType),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_WSC_PIN:
			memcpy( &(((mib_t *)mib)->wlan->wscPin),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_XCAP:
			memcpy( &(((mib_t *)mib)->wlan->xCap),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_WLAN_ADDR1:
			memcpy( &(((mib_t *)mib)->wlan->macAddr1),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_WLAN_ADDR2:
			memcpy( &(((mib_t *)mib)->wlan->macAddr2),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_WLAN_ADDR3:
			memcpy( &(((mib_t *)mib)->wlan->macAddr3),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_WLAN_ADDR4:
			memcpy( &(((mib_t *)mib)->wlan->macAddr4),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_WLAN_ADDR5:
			memcpy( &(((mib_t *)mib)->wlan->macAddr5),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_WLAN_ADDR6:
			memcpy( &(((mib_t *)mib)->wlan->macAddr6),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_WLAN_ADDR7:
			memcpy( &(((mib_t *)mib)->wlan->macAddr7),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_TSSI1:
			memcpy( &(((mib_t *)mib)->wlan->TSSI1),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_TSSI2:
			memcpy( &(((mib_t *)mib)->wlan->TSSI2),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_THER:
			memcpy( &(((mib_t *)mib)->wlan->Ther),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_TRSWITCH:
			memcpy( &(((mib_t *)mib)->wlan->trswitch),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_TRSWPAPE_C9:
			memcpy( &(((mib_t *)mib)->wlan->trswpape_c9),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_TRSWPAPE_CC:
			memcpy( &(((mib_t *)mib)->wlan->trswpape_cc),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_TARGET_PWR:
			memcpy( &(((mib_t *)mib)->wlan->target_pwr),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_RESERVED5:
			memcpy( &(((mib_t *)mib)->wlan->Reserved5),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_RESERVED6:
			memcpy( &(((mib_t *)mib)->wlan->Reserved6),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_RESERVED7:
			memcpy( &(((mib_t *)mib)->wlan->Reserved7),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_RESERVED8:
			memcpy( &(((mib_t *)mib)->wlan->Reserved8),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_TX_POWER_CCK_A:
			memcpy( &(((mib_t *)mib)->wlan->pwrlevelCCK_A),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_TX_POWER_CCK_B:
			memcpy( &(((mib_t *)mib)->wlan->pwrlevelCCK_B),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_TX_POWER_HT40_1S_A:
			memcpy( &(((mib_t *)mib)->wlan->pwrlevelHT40_1S_A),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_TX_POWER_HT40_1S_B:
			memcpy( &(((mib_t *)mib)->wlan->pwrlevelHT40_1S_B),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_TX_POWER_DIFF_HT40_2S:
			memcpy( &(((mib_t *)mib)->wlan->pwrdiffHT40_2S),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_TX_POWER_DIFF_HT20:
			memcpy( &(((mib_t *)mib)->wlan->pwrdiffHT20),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_TX_POWER_DIFF_OFDM:
			memcpy( &(((mib_t *)mib)->wlan->pwrdiffOFDM),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_RESERVED9:
			memcpy( &(((mib_t *)mib)->wlan->Reserved9),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_11N_RESERVED10:
			memcpy( &(((mib_t *)mib)->wlan->Reserved10),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_TX_POWER_5G_HT40_1S_A:
			memcpy( &(((mib_t *)mib)->wlan->pwrlevel5GHT40_1S_A),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_TX_POWER_5G_HT40_1S_B:
			memcpy( &(((mib_t *)mib)->wlan->pwrlevel5GHT40_1S_B),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_TX_POWER_DIFF_5G_HT40_2S:
			memcpy( &(((mib_t *)mib)->wlan->pwrdiff5GHT40_2S),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_TX_POWER_DIFF_5G_HT20:
			memcpy( &(((mib_t *)mib)->wlan->pwrdiff5GHT20),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		case MIB_HW_TX_POWER_DIFF_5G_OFDM:
			memcpy( &(((mib_t *)mib)->wlan->pwrdiff5GOFDM),
					tbl + i,
					swap16(mibtbl.size) );
			break;
		default:
			printv( "unknown field (type %i) found,"
				"containing data:\n",
				swap16(mibtbl.type) );
			if ( verbose )
				print_hex( tbl + i, swap16(mibtbl.size) );
			break;
		}

		i += swap16(mibtbl.size);
	}
}

static int hex_to_string( unsigned char *hex, char *str, int len )
{
	int i;
	unsigned char *d, *s;
	const static char hexdig[] = "0123456789abcdef";

	if ( hex == NULL || str == NULL )
		return -1;

	d = (unsigned char *)str;
	s = hex;

	for ( i = 0; i < len; i++,s++ ) {
		*d++ = hexdig[(*s >> 4) & 0xf];
		*d++ = hexdig[*s & 0xf];
	}

	*d = 0;
	return 0;
}

#ifdef HAVE_RTK_AC_SUPPORT

#define B1_G1	40
#define B1_G2	48

#define B2_G1	56
#define B2_G2	64

#define B3_G1	104
#define B3_G2	112
#define B3_G3	120
#define B3_G4	128
#define B3_G5	136
#define B3_G6	144

#define B4_G1	153
#define B4_G2	161
#define B4_G3	169
#define B4_G4	177

void assign_diff_AC(unsigned char* pMib, unsigned char* pVal)
{
	int x=0, y=0;

	memset((pMib+35), pVal[0], (B1_G1-35));
	memset((pMib+B1_G1), pVal[1], (B1_G2-B1_G1));
	memset((pMib+B1_G2), pVal[2], (B2_G1-B1_G2));
	memset((pMib+B2_G1), pVal[3], (B2_G2-B2_G1));
	memset((pMib+B2_G2), pVal[4], (B3_G1-B2_G2));
	memset((pMib+B3_G1), pVal[5], (B3_G2-B3_G1));
	memset((pMib+B3_G2), pVal[6], (B3_G3-B3_G2));
	memset((pMib+B3_G3), pVal[7], (B3_G4-B3_G3));
	memset((pMib+B3_G4), pVal[8], (B3_G5-B3_G4));
	memset((pMib+B3_G5), pVal[9], (B3_G6-B3_G5));
	memset((pMib+B3_G6), pVal[10], (B4_G1-B3_G6));
	memset((pMib+B4_G1), pVal[11], (B4_G2-B4_G1));
	memset((pMib+B4_G2), pVal[12], (B4_G3-B4_G2));
	memset((pMib+B4_G3), pVal[13], (B4_G4-B4_G3));

}

void assign_diff_AC_hex_to_string(unsigned char* pmib,char* str,int len)
{
	char mib_buf[MAX_5G_CHANNEL_NUM_MIB];
	memset(mib_buf,0,sizeof(mib_buf));
	assign_diff_AC(mib_buf, pmib);
	hex_to_string(mib_buf,str,MAX_5G_CHANNEL_NUM_MIB);
}
#endif /* HAVE_RTK_AC_SUPPORT */

void set_tx_calibration( mib_wlan_t *phw, char *interface )
{
	if( !phw )
		return;

	char p[ MAX_5G_CHANNEL_NUM_MIB * 2 + 1 ];

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrlevelCCK_A, p, MAX_2G_CHANNEL_NUM_MIB );
	printf( "pwrlevelCCK_A=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrlevelCCK_B, p, MAX_2G_CHANNEL_NUM_MIB );
	printf( "pwrlevelCCK_B=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrlevelHT40_1S_A, p, MAX_2G_CHANNEL_NUM_MIB );
	printf( "pwrlevelHT40_1S_A=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrlevelHT40_1S_B, p, MAX_2G_CHANNEL_NUM_MIB );
	printf( "pwrlevelHT40_1S_B=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrdiffHT40_2S, p, MAX_2G_CHANNEL_NUM_MIB );
	printf( "pwrdiffHT40_2S=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrdiffHT20, p, MAX_2G_CHANNEL_NUM_MIB );
	printf( "pwrdiffHT20=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrdiffOFDM, p, MAX_2G_CHANNEL_NUM_MIB );
	printf( "pwrdiffOFDM=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrlevel5GHT40_1S_A, p, MAX_5G_CHANNEL_NUM_MIB );
	printf( "pwrlevel5GHT40_1S_A=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrlevel5GHT40_1S_B, p, MAX_5G_CHANNEL_NUM_MIB );
	printf( "pwrlevel5GHT40_1S_B=%s\n", p );

#ifdef HAVE_RTK_92D_SUPPORT
	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrdiff5GHT40_2S, p, MAX_5G_CHANNEL_NUM_MIB );
	printf( "pwrdiff5GHT40_2S=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrdiff5GHT20, p, MAX_5G_CHANNEL_NUM_MIB );
	printf( "pwrdiff5GHT20=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrdiff5GOFDM, p, MAX_5G_CHANNEL_NUM_MIB );
	printf( "pwrdiff5GOFDM=%s\n", p );
#endif /* HAVE_RTK_92D_SUPPORT */

#ifdef HAVE_RTK_AC_SUPPORT /* 8812 */
	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrdiff_20BW1S_OFDM1T_A, p, MAX_2G_CHANNEL_NUM_MIB );
	printf( "pwrdiff_20BW1S_OFDM1T_A=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrdiff_40BW2S_20BW2S_A, p, MAX_2G_CHANNEL_NUM_MIB );
	printf( "pwrdiff_40BW2S_20BW2S_A=%s\n", p );

	memset( p, 0, sizeof(p) );
	assign_diff_AC_hex_to_string( phw->pwrdiff_5G_20BW1S_OFDM1T_A, p, MAX_5G_DIFF_NUM );
	printf( "pwrdiff_5G_20BW1S_OFDM1T_A=%s\n", p );

	memset( p, 0, sizeof(p) );
	assign_diff_AC_hex_to_string( phw->pwrdiff_5G_40BW2S_20BW2S_A, p, MAX_5G_DIFF_NUM );
	printf( "pwrdiff_5G_40BW2S_20BW2S_A=%s\n", p );

	memset( p, 0, sizeof(p) );
	assign_diff_AC_hex_to_string( phw->pwrdiff_5G_80BW1S_160BW1S_A, p, MAX_5G_DIFF_NUM );
	printf( "pwrdiff_5G_80BW1S_160BW1S_A=%s\n", p );

	memset( p, 0, sizeof(p) );
	assign_diff_AC_hex_to_string( phw->pwrdiff_5G_80BW2S_160BW2S_A, p, MAX_5G_DIFF_NUM );
	printf( "pwrdiff_5G_80BW2S_160BW2S_A=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrdiff_20BW1S_OFDM1T_B, p, MAX_2G_CHANNEL_NUM_MIB );
	printf( "pwrdiff_20BW1S_OFDM1T_B=%s\n", p );

	memset( p, 0, sizeof(p) );
	hex_to_string( phw->pwrdiff_40BW2S_20BW2S_B, p, MAX_2G_CHANNEL_NUM_MIB );
	printf( "pwrdiff_40BW2S_20BW2S_B=%s\n", p );

	memset( p, 0, sizeof(p) );
	assign_diff_AC_hex_to_string( phw->pwrdiff_5G_20BW1S_OFDM1T_B, p, MAX_5G_DIFF_NUM );
	printf( "pwrdiff_5G_20BW1S_OFDM1T_B=%s\n", p );

	memset( p, 0, sizeof(p) );
	assign_diff_AC_hex_to_string( phw->pwrdiff_5G_40BW2S_20BW2S_B, p, MAX_5G_DIFF_NUM );
	printf( "pwrdiff_5G_40BW2S_20BW2S_B=%s\n", p );

	memset( p, 0, sizeof(p) );
	assign_diff_AC_hex_to_string( phw->pwrdiff_5G_80BW1S_160BW1S_B, p, MAX_5G_DIFF_NUM );
	printf( "pwrdiff_5G_80BW1S_160BW1S_B=%s\n", p );

	memset( p, 0, sizeof(p) );
	assign_diff_AC_hex_to_string( phw->pwrdiff_5G_80BW2S_160BW2S_B, p, MAX_5G_DIFF_NUM );
	printf( "pwrdiff_5G_80BW2S_160BW2S_B=%s\n", p );
#endif /* HAVE_RTK_AC_SUPPORT */
}

int main( int argc, char **argv )
{
	int efuse = 0; /* HAVE_RTK_EFUSE */

	char infile[ 255 ] = "";
	char outfile[ 255 ] = "";
	unsigned int mib_offset = MIB_OFFSET;
	uint32_t get = MIB_HW_BOARD_VER;

	int opt;
	int option_index = 0;
	while ( (opt = getopt_long( argc, argv,
					opt_string, long_options,
					&option_index )) != -1 )
	{
		switch( opt ) {
		case 'g':
			if ( !strncmp( optarg, "macs", 5 ) ) {
				get = MIB_HW_MACS;
			} else if ( !strncmp( optarg, "mac0", 5 ) ) {
				get = MIB_HW_NIC0_ADDR;
			} else if ( !strncmp( optarg, "mac1", 5 ) ) {
				get = MIB_HW_NIC1_ADDR;
			} else if ( !strncmp( optarg, "wmac0", 6 ) ) {
				get = MIB_HW_WLAN_ADDR;
			} else if ( !strncmp( optarg, "wcal", 5 ) ) {
				get = MIB_HW_WCAL;
			} else if ( !strncmp( optarg, "ver", 4 ) ) {
				get = MIB_HW_BOARD_VER;
			}
			break;
		case 'i':
			snprintf( infile, sizeof infile, "%s", optarg );
			break;
		case 'o':
			mib_offset = (unsigned int)atoi(optarg);
			break;
		case 'O':
			snprintf( outfile, sizeof outfile, "%s", optarg );
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		case 'v':
			verbose = 1;
			break;
		case '?':
		default:
			printf( "%s: option -%c is invalid\n", argv[0], optopt );
			exit(EXIT_FAILURE);
		}
	}

	if ( strlen(infile) < 1 )
		snprintf( infile, sizeof infile, "%s", FLASH_DEVICE_NAME );

	unsigned char *buf = NULL;
	unsigned char *mib = NULL;
	unsigned char *tmp = NULL;
	int mib_len = 0;
	uint32_t size = 0;

	if ( efuse ) {
		printv( "Efuse enabled. Nothing to do!\n" );
		exit(EXIT_SUCCESS);
	}

	mib_len = mib_read( infile, mib_offset,	&buf, &size );

	if ( mib_len == MIB_ERR_GENERIC )
		goto exit;

	if ( mib_len == MIB_ERR_COMPRESSED ) {
		mib_len = mib_decode( buf, size, &tmp );

		printv( "Compressed size: %i\n", size );
		mib_hdr_t *header = (mib_hdr_t *)tmp;
		printv( "Header signature: '%.2s'\n", header->sig );
		printv( "Length from header: 0x%x\n", swap16(header->len) );
		printv( "Decoded length: 0x%x\n", mib_len );
		printv( "Expected mininum len: 0x%x\n", (int)sizeof(mib_t) );
		printv( "Decoded data:\n" );
		if ( verbose )
			print_hex( tmp + sizeof(mib_hdr_t), mib_len );

		free(buf);
		buf = (unsigned char *)malloc( sizeof(mib_t) );
		memset( buf, 0, sizeof(mib_t) );
		mibtbl_to_struct( tmp + sizeof(mib_hdr_t), mib_len, buf );
	}

	mib = buf;

	if ( mib_len < (int)sizeof(mib_t) ) {
		printv( "MIB length invalid!\n" );
		goto exit;
	}

	printv( "board version: 0x%02x\n", mib[0]);

	switch (get) {
	case MIB_HW_MACS:
		print_mac( (unsigned char *)(((mib_t *)mib)->nic0_addr) );
		printf("\n");
		print_mac( (unsigned char *)(((mib_t *)mib)->nic1_addr) );
		printf("\n");
		print_mac( (unsigned char *)(((mib_t *)mib)->wlan->macAddr) );
		printf("\n");
		print_mac( (unsigned char *)(((mib_t *)mib)->wlan->macAddr1) );
		printf("\n");
		print_mac( (unsigned char *)(((mib_t *)mib)->wlan->macAddr2) );
		printf("\n");
		print_mac( (unsigned char *)(((mib_t *)mib)->wlan->macAddr3) );
		printf("\n");
		print_mac( (unsigned char *)(((mib_t *)mib)->wlan->macAddr4) );
		printf("\n");
		print_mac( (unsigned char *)(((mib_t *)mib)->wlan->macAddr5) );
		printf("\n");
		print_mac( (unsigned char *)(((mib_t *)mib)->wlan->macAddr6) );
		printf("\n");
		print_mac( (unsigned char *)(((mib_t *)mib)->wlan->macAddr7) );
		printf("\n");
		break;
	case MIB_HW_NIC0_ADDR:
		print_mac( (unsigned char *)(((mib_t *)mib)->nic0_addr) );
		break;
	case MIB_HW_NIC1_ADDR:
		print_mac( (unsigned char *)(((mib_t *)mib)->nic1_addr) );
		break;
	case MIB_HW_WLAN_ADDR:
		print_mac( (unsigned char *)(((mib_t *)mib)->wlan->macAddr) );
		break;
	case MIB_HW_WCAL:
		set_tx_calibration( (mib_wlan_t *)( mib + MIB_WLAN_OFFSET ),
								  "wlan0" );
#ifdef HAVE_RTK_DUAL_BAND_SUPPORT
		set_tx_calibration((mib_wlan_t *)
				   ( mib + MIB_WLAN_OFFSET + sizeof(mib_wlan_t),
								  "wlan1" );
#endif
		break;
	case MIB_HW_BOARD_VER:
	default:
		printf( "Board version: %i\n",
			(((mib_t *)mib)->board_ver) );
		break;
	}

exit:
	free(buf);
	if ( mib != buf )
		free(tmp);

	exit(EXIT_SUCCESS);
}
