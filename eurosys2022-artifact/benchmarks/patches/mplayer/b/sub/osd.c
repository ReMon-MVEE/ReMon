/*
 * generic alpha renderers for all YUV modes and RGB depths
 * These are "reference implementations", should be optimized later (MMX, etc).
 * templating code by Michael Niedermayer (michaelni@gmx.at)
 *
 * This file is part of MPlayer.
 *
 * MPlayer is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * MPlayer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with MPlayer; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

//#define FAST_OSD
//#define FAST_OSD_TABLE

#include "config.h"
#include "osd.h"
#include "mp_msg.h"
#include <inttypes.h>
#include <stdlib.h>
#include "libmpcodecs/img_format.h"
#include "cpudetect.h"

#if ARCH_X86
static const uint64_t bFF __attribute__((aligned(8))) = 0xFFFFFFFFFFFFFFFFULL;
static const unsigned long long mask24lh  __attribute__((aligned(8))) = 0xFFFF000000000000ULL;
static const unsigned long long mask24hl  __attribute__((aligned(8))) = 0x0000FFFFFFFFFFFFULL;
#endif

#define COMPILE_C

#undef HAVE_MMX
#undef HAVE_MMX2
#undef HAVE_AMD3DNOW
#define HAVE_MMX 0
#define HAVE_MMX2 0
#define HAVE_AMD3DNOW 0
#define RENAME(a) a ## _C
#include "osd_template.c"

void vo_draw_alpha_yv12(int w,int h, unsigned char* src, unsigned char *srca, int srcstride, unsigned char* dstbase,int dststride){
    vo_draw_alpha_yv12_C(w, h, src, srca, srcstride, dstbase, dststride);
}

void vo_draw_alpha_yuy2(int w,int h, unsigned char* src, unsigned char *srca, int srcstride, unsigned char* dstbase,int dststride){
    vo_draw_alpha_yuy2_C(w, h, src, srca, srcstride, dstbase, dststride);
}

void vo_draw_alpha_uyvy(int w,int h, unsigned char* src, unsigned char *srca, int srcstride, unsigned char* dstbase,int dststride){
    vo_draw_alpha_uyvy_C(w, h, src, srca, srcstride, dstbase, dststride);
}

void vo_draw_alpha_rgb24(int w,int h, unsigned char* src, unsigned char *srca, int srcstride, unsigned char* dstbase,int dststride){
    vo_draw_alpha_rgb24_C(w, h, src, srca, srcstride, dstbase, dststride);
}

void vo_draw_alpha_rgb32(int w,int h, unsigned char* src, unsigned char *srca, int srcstride, unsigned char* dstbase,int dststride){
    vo_draw_alpha_rgb32_C(w, h, src, srca, srcstride, dstbase, dststride);
}

#ifdef FAST_OSD_TABLE
static unsigned short fast_osd_12bpp_table[256];
static unsigned short fast_osd_15bpp_table[256];
static unsigned short fast_osd_16bpp_table[256];
#endif

void vo_draw_alpha_init(void){
#ifdef FAST_OSD_TABLE
    int i;
    for(i=0;i<256;i++){
        fast_osd_12bpp_table[i]=((i>>4)<< 8)|((i>>4)<<4)|(i>>4);
        fast_osd_15bpp_table[i]=((i>>3)<<10)|((i>>3)<<5)|(i>>3);
        fast_osd_16bpp_table[i]=((i>>3)<<11)|((i>>2)<<5)|(i>>3);
    }
#endif
//FIXME the optimized stuff is a lie for 15/16bpp as they aren't optimized yet
	if( mp_msg_test(MSGT_OSD,MSGL_V) )
	{
#if CONFIG_RUNTIME_CPUDETECT
#if ARCH_X86
		// ordered per speed fasterst first
		if(gCpuCaps.hasMMX2)
			mp_msg(MSGT_OSD,MSGL_INFO,"Using MMX (with tiny bit MMX2) Optimized OnScreenDisplay\n");
		else if(gCpuCaps.has3DNow)
			mp_msg(MSGT_OSD,MSGL_INFO,"Using MMX (with tiny bit 3DNow) Optimized OnScreenDisplay\n");
		else if(gCpuCaps.hasMMX)
			mp_msg(MSGT_OSD,MSGL_INFO,"Using MMX Optimized OnScreenDisplay\n");
		else
			mp_msg(MSGT_OSD,MSGL_INFO,"Using X86 Optimized OnScreenDisplay\n");
#else
			mp_msg(MSGT_OSD,MSGL_INFO,"Using Unoptimized OnScreenDisplay\n");
#endif
#else //CONFIG_RUNTIME_CPUDETECT
#if HAVE_MMX2
			mp_msg(MSGT_OSD,MSGL_INFO,"Using MMX (with tiny bit MMX2) Optimized OnScreenDisplay\n");
#elif HAVE_AMD3DNOW
			mp_msg(MSGT_OSD,MSGL_INFO,"Using MMX (with tiny bit 3DNow) Optimized OnScreenDisplay\n");
#elif HAVE_MMX
			mp_msg(MSGT_OSD,MSGL_INFO,"Using MMX Optimized OnScreenDisplay\n");
#elif ARCH_X86
			mp_msg(MSGT_OSD,MSGL_INFO,"Using X86 Optimized OnScreenDisplay\n");
#else
			mp_msg(MSGT_OSD,MSGL_INFO,"Using Unoptimized OnScreenDisplay\n");
#endif
#endif //!CONFIG_RUNTIME_CPUDETECT
	}
}

void vo_draw_alpha_rgb12(int w, int h, unsigned char* src, unsigned char *srca,
                         int srcstride, unsigned char* dstbase, int dststride) {
    int y;
    for (y = 0; y < h; y++) {
        register unsigned short *dst = (unsigned short*) dstbase;
        register int x;
        for (x = 0; x < w; x++) {
            if(srca[x]){
#ifdef FAST_OSD
#ifdef FAST_OSD_TABLE
                dst[x] = fast_osd_12bpp_table[src[x]];
#else
                register unsigned int a = src[x] >> 4;
                dst[x] = (a << 8) | (a << 4) | a;
#endif
#else
                unsigned char r = dst[x] & 0x0F;
                unsigned char g = (dst[x] >> 4) & 0x0F;
                unsigned char b = (dst[x] >> 8) & 0x0F;
                r = (((r*srca[x]) >> 4) + src[x]) >> 4;
                g = (((g*srca[x]) >> 4) + src[x]) >> 4;
                b = (((b*srca[x]) >> 4) + src[x]) >> 4;
                dst[x] = (b << 8) | (g << 4) | r;
#endif
            }
        }
        src += srcstride;
        srca += srcstride;
        dstbase += dststride;
    }
    return;
}

void vo_draw_alpha_rgb15(int w,int h, unsigned char* src, unsigned char *srca, int srcstride, unsigned char* dstbase,int dststride){
    int y;
    for(y=0;y<h;y++){
        register unsigned short *dst = (unsigned short*) dstbase;
        register int x;
        for(x=0;x<w;x++){
            if(srca[x]){
#ifdef FAST_OSD
#ifdef FAST_OSD_TABLE
                dst[x]=fast_osd_15bpp_table[src[x]];
#else
		register unsigned int a=src[x]>>3;
                dst[x]=(a<<10)|(a<<5)|a;
#endif
#else
                unsigned char r=dst[x]&0x1F;
                unsigned char g=(dst[x]>>5)&0x1F;
                unsigned char b=(dst[x]>>10)&0x1F;
                r=(((r*srca[x])>>5)+src[x])>>3;
                g=(((g*srca[x])>>5)+src[x])>>3;
                b=(((b*srca[x])>>5)+src[x])>>3;
                dst[x]=(b<<10)|(g<<5)|r;
#endif
            }
        }
        src+=srcstride;
        srca+=srcstride;
        dstbase+=dststride;
    }
    return;
}

void vo_draw_alpha_rgb16(int w,int h, unsigned char* src, unsigned char *srca, int srcstride, unsigned char* dstbase,int dststride){
    int y;
    for(y=0;y<h;y++){
        register unsigned short *dst = (unsigned short*) dstbase;
        register int x;
        for(x=0;x<w;x++){
            if(srca[x]){
#ifdef FAST_OSD
#ifdef FAST_OSD_TABLE
                dst[x]=fast_osd_16bpp_table[src[x]];
#else
                dst[x]=((src[x]>>3)<<11)|((src[x]>>2)<<5)|(src[x]>>3);
#endif
#else
                unsigned char r=dst[x]&0x1F;
                unsigned char g=(dst[x]>>5)&0x3F;
                unsigned char b=(dst[x]>>11)&0x1F;
                r=(((r*srca[x])>>5)+src[x])>>3;
                g=(((g*srca[x])>>6)+src[x])>>2;
                b=(((b*srca[x])>>5)+src[x])>>3;
                dst[x]=(b<<11)|(g<<5)|r;
#endif
            }
        }
        src+=srcstride;
        srca+=srcstride;
        dstbase+=dststride;
    }
    return;
}

vo_draw_alpha_func vo_get_draw_alpha(unsigned fmt) {
    if (IMGFMT_IS_RGB(fmt) || IMGFMT_IS_BGR(fmt)) {
        switch (IMGFMT_RGB_DEPTH(fmt))
        {
        case 12:
            return vo_draw_alpha_rgb12;
        case 15:
            return vo_draw_alpha_rgb15;
        case 16:
            return vo_draw_alpha_rgb16;
        case 24:
            return vo_draw_alpha_rgb24;
        case 32:
            return vo_draw_alpha_rgb32;
        }
        return NULL;
    }
    switch (fmt) {
    case IMGFMT_YV12:
    case IMGFMT_I420:
    case IMGFMT_IYUV:
    case IMGFMT_NV12:
    case IMGFMT_NV21:
        return vo_draw_alpha_yv12;
    case IMGFMT_YUY2:
    case IMGFMT_YVYU:
        return vo_draw_alpha_yuy2;
    case IMGFMT_UYVY:
        return vo_draw_alpha_uyvy;
    }
    return NULL;
}
