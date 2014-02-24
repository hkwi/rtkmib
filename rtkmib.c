#include <getopt.h>

#include "rtkmib.h"

#define NAME		"rtkmib"
#define VERSION		"0.0.1"


static const char *opt_string = ":i:o:h";
static struct option long_options[] = {
	{ "input", required_argument, NULL, 'i' },
	{ "output", required_argument, NULL, 'o' },
	{ "help", no_argument, NULL, 'h' },
	{ 0, 0, 0, 0 },
};

void usage ( char *pname ) {
	char **dp;
	char *optdoc[] = {
		"\n",
		"   Options:\n",
		"   -i, --input            input file name\n",
		"   -o, --output           output file name\n",
		"   -h, --help             print this help message\n",
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

static int flash_read( char *mtd, int offset, int len, char *buf )
{
	if ( !buf || !mtd || len < 0 )
		return -1;

	int err = 0;
	int fd = open( mtd, O_RDONLY );

	if ( fd < 0 ) {
		printf( "Flash read error: %m\n" );
		return fd;
	}

	if ( offset > 0 )
		lseek( fd, offset, SEEK_SET );

	if ( read( fd, buf, len ) != len )
		err = -1;

	close( fd );

	return err;
}

inline uint16_t swap16( uint16_t x )
{
	uint16_t b = x;
	b = (x >> 8) & 0xff;
	return b | (x << 8);
}

inline uint32_t swap32( uint32_t x )
{
	return x = (x >> 24) |
		((x << 8) & 0x00ff0000) |
		((x >> 8) & 0x0000ff00) |
		(x << 24);
}

#define RING_SIZE       4096    /* size of ring buffer */
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

	memset( text_buf, 0, RING_SIZE + UL_MATCH - 1 );
	memset( *out, 0, len );

	while (1) {
		if ( ((flags >>= 1) & 256) == 0 ) {
			pos++;
			if ( pos > len )
				break;
			c = in[ pos ];		/* get flags for frame */
			flags = c | 0xff00;	/* uses higher byte cleverly */
		}				/* to count eight */
		/* test next flag bit */
		if ( flags & 1 ) {
			/* flag bit of 1 means unencoded byte */
			pos++;
			if ( pos > len )
				break;
			c = in[ pos ];
			explen++;
			if ( explen > len )
				*out = (unsigned char *)realloc( *out, explen + 1 );
			(*out)[ explen ] = c;		/* copy to output */
			printf("%i: %x\n", explen - 1, c); fflush(stdout);
			text_buf[ r++ ] = c;		/* and to text_buf */
			r &= (RING_SIZE - 1);
		} else {
			/* 0 means encoded info */
			pos++;
			if ( pos > len )
				break;
			i = in[ pos ];		/* get position */
			pos++; // ???
			if ( pos > len )
				break;
			j = in[ pos ];		/* get length of run */

			i |= ((j & 0xf0) << 4);	    /* i is now offset of run */
			j = (j & 0x0f) + THRESHOLD; /* j is the length */

			for ( k = 0; k <= j; k++ ) {
				c = text_buf[ (i + k) & (RING_SIZE - 1) ];
				explen++;
				if ( explen > len )
					*out = (unsigned char *)realloc( (void *)*out, explen + 1 );
				(*out)[ explen ] = c;
				printf("c%i: %x\n", explen - 1, c); fflush(stdout);
				text_buf[ r++ ] = c;
				r &= (RING_SIZE - 1);
			}
		}
	}

	free(text_buf);
	return explen;
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
		syslog( LOG_ERR, "probe header failed\n" );
		return MIB_ERR_GENERIC;
	}

	if ( !memcmp( MIB_HEADER_COMPR_TAG,
		      header.sig,
		      sizeof(header.sig) ) )
	{
		printf( "MIB is compressed!\n" );
		if ( flash_read( mtd, offset, sizeof(mib_hdr_compr_t),
						(char *)&header_compr ) )
		{
			syslog( LOG_ERR, "read header failed\n" );
			return MIB_ERR_GENERIC;
		}
		sig = header_compr.sig;
		len = swap32(header_compr.len);
		compression = swap16(header_compr.factor);
	} else {
		sig = header.sig;
		len = swap16(header.len);
	}

	printf( "Header info:\n" );
	printf( "  signature: '%s'\n", sig );
	printf( "  data size: 0x%x\n", len );

	*mib = (unsigned char *)malloc(len);

	if ( compression ) {
		printf( "  compression factor: 0x%x\n", compression );
		*size = len;
		if ( flash_read( mtd, offset + sizeof(mib_hdr_compr_t),
				 len, (char *)*mib ) )
		{
			syslog( LOG_ERR, "MIB read failed\n" );
			return MIB_ERR_GENERIC;
		}
		return MIB_ERR_COMPRESSED;
	}

	if ( flash_read( mtd, offset + sizeof(mib_hdr_t),
			 len, (char *)*mib ) )
	{
		syslog( LOG_ERR, "MIB read failed\n" );
		return MIB_ERR_GENERIC;
	}

	return len;
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

int set_tx_calibration( mib_wlan_t *phw, char *interface )
{
	char tmpbuff[1024], p[ MAX_5G_CHANNEL_NUM_MIB * 2 + 1 ];
	if(!phw)
		return -1;

	hex_to_string(phw->pwrlevelCCK_A,p,MAX_2G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrlevelCCK_A=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	hex_to_string(phw->pwrlevelCCK_B,p,MAX_2G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrlevelCCK_B=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	hex_to_string(phw->pwrlevelHT40_1S_A,p,MAX_2G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrlevelHT40_1S_A=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	hex_to_string(phw->pwrlevelHT40_1S_B,p,MAX_2G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrlevelHT40_1S_B=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	hex_to_string(phw->pwrdiffHT40_2S,p,MAX_2G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiffHT40_2S=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	hex_to_string(phw->pwrdiffHT20,p,MAX_2G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiffHT20=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	hex_to_string(phw->pwrdiffOFDM,p,MAX_2G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiffOFDM=%s",interface,p);
//	system(tmpbuff);

	hex_to_string(phw->pwrlevel5GHT40_1S_A,p,MAX_5G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrlevel5GHT40_1S_A=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	hex_to_string(phw->pwrlevel5GHT40_1S_B,p,MAX_5G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrlevel5GHT40_1S_B=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

#ifdef HAVE_RTK_92D_SUPPORT
	hex_to_string(phw->pwrdiff5GHT40_2S,p,MAX_5G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff5GHT40_2S=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	hex_to_string(phw->pwrdiff5GHT20,p,MAX_5G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff5GHT20=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	hex_to_string(phw->pwrdiff5GOFDM,p,MAX_5G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff5GOFDM=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);
#endif /* HAVE_RTK_92D_SUPPORT */

#ifdef HAVE_RTK_AC_SUPPORT /* 8812 */
	hex_to_string(phw->pwrdiff_20BW1S_OFDM1T_A,p,MAX_2G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff_20BW1S_OFDM1T_A=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	hex_to_string(phw->pwrdiff_40BW2S_20BW2S_A,p,MAX_2G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff_40BW2S_20BW2S_A=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	assign_diff_AC_hex_to_string(phw->pwrdiff_5G_20BW1S_OFDM1T_A,p,MAX_5G_DIFF_NUM);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff_5G_20BW1S_OFDM1T_A=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	assign_diff_AC_hex_to_string(phw->pwrdiff_5G_40BW2S_20BW2S_A,p,MAX_5G_DIFF_NUM);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff_5G_40BW2S_20BW2S_A=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	assign_diff_AC_hex_to_string(phw->pwrdiff_5G_80BW1S_160BW1S_A,p,MAX_5G_DIFF_NUM);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff_5G_80BW1S_160BW1S_A=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	assign_diff_AC_hex_to_string(phw->pwrdiff_5G_80BW2S_160BW2S_A,p,MAX_5G_DIFF_NUM);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff_5G_80BW2S_160BW2S_A=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	hex_to_string(phw->pwrdiff_20BW1S_OFDM1T_B,p,MAX_2G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff_20BW1S_OFDM1T_B=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	hex_to_string(phw->pwrdiff_40BW2S_20BW2S_B,p,MAX_2G_CHANNEL_NUM_MIB);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff_40BW2S_20BW2S_B=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	assign_diff_AC_hex_to_string(phw->pwrdiff_5G_20BW1S_OFDM1T_B,p,MAX_5G_DIFF_NUM);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff_5G_20BW1S_OFDM1T_B=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	assign_diff_AC_hex_to_string(phw->pwrdiff_5G_40BW2S_20BW2S_B,p,MAX_5G_DIFF_NUM);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff_5G_40BW2S_20BW2S_B=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	assign_diff_AC_hex_to_string(phw->pwrdiff_5G_80BW1S_160BW1S_B,p,MAX_5G_DIFF_NUM);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff_5G_80BW1S_160BW1S_B=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);

	assign_diff_AC_hex_to_string(phw->pwrdiff_5G_80BW2S_160BW2S_B,p,MAX_5G_DIFF_NUM);
	sprintf(tmpbuff,"iwpriv %s set_mib pwrdiff_5G_80BW2S_160BW2S_B=%s",interface,p);
//	system(tmpbuff);
	printf("%s\n",tmpbuff);
#endif /* HAVE_RTK_AC_SUPPORT */

	return 0;
}

int main( int argc, char **argv )
{
	int efuse = 0; /* HAVE_RTK_EFUSE */

	char infile[ 255 ] = "";
	char outfile[ 255 ] = "";
	unsigned int mib_offset = MIB_OFFSET;

	int opt;
	int option_index = 0;
	while ( (opt = getopt_long( argc, argv,
					opt_string, long_options,
					&option_index )) != -1 )
	{
		switch( opt ) {
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
	int mib_len = 0;
	uint32_t compr_size = 0;
	mib_wlan_t *mib_wlan;

	if ( efuse ) {
		syslog( LOG_WARNING,"Efuse enabled. Nothing to do!\n" );
		exit(EXIT_SUCCESS);
	}

	mib_len = mib_read( infile, mib_offset,	&buf, &compr_size );

	if ( mib_len == MIB_ERR_GENERIC )
		goto exit;

	if ( mib_len == MIB_ERR_COMPRESSED ) {
		printf("Compressed size: %i\n", compr_size);
		mib_len = mib_decode( buf, compr_size, &mib );
	} else {
		mib = buf;
	}

	printf( "MIB len: %i\n", mib_len );
	printf( "Expected mininum len: %i\n", (int)sizeof(mib_t) );

	if ( mib_len < (int)sizeof(mib_t) ) {
		syslog( LOG_ERR, "MIB length invalid!\n" );
		goto exit;
	}

//	mib_hdr_t *header = (mib_hdr_t *)mib;
//	printf("%s\n", header->sig);
//	printf("%i\n", header->len);

	printf("board version: %02x\n", mib[0]);
	printf("nic0: %02x:%02x:%02x:%02x:%02x:%02x\n",
				mib[1], mib[2], mib[3],
				mib[4], mib[5], mib[6] );
	printf("nic1: %02x:%02x:%02x:%02x:%02x:%02x\n",
				mib[7], mib[8], mib[9],
				mib[10], mib[11], mib[12] );
	printf("wlan0: %02x:%02x:%02x:%02x:%02x:%02x\n",
				mib[13], mib[14], mib[15],
				mib[16], mib[17], mib[18] );
	printf("wlan1: %02x:%02x:%02x:%02x:%02x:%02x\n",
				mib[19], mib[20], mib[21],
				mib[22], mib[23], mib[24] );

	mib_wlan = (mib_wlan_t *)( mib + MIB_WLAN_OFFSET );
	set_tx_calibration( mib_wlan, "wlan0" );

#ifdef HAVE_RTK_DUAL_BAND_SUPPORT
	mib_wlan = (mib_wlan_t *)( mib + MIB_WLAN_OFFSET + sizeof(mib_wlan_t) );
	set_tx_calibration( mib_wlan, "wlan1" );
#endif
exit:
	free(buf);
	if ( mib != buf )
		free(mib);

	exit(EXIT_SUCCESS);
}
