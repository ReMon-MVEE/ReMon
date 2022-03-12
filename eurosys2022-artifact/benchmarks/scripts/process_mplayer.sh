#!/bin/bash
set -e

cd "$(readlink -f $(dirname ${BASH_SOURCE})/../results/mplayer/)"

process_max_fps ()
{
    __results=($(grep BENCHMARKs $1 | cut -d '=' -f2 | cut -d 's' -f1))
    __sum=$(echo "${__results[*]}"|sed "s/ /+/g")
    __count=${#__results[@]}
    echo " > $2: $(python -c "print(($__sum)/$__count.0)")"
    
}

process_framedrop ()
{
    __results=($(grep BENCHMARKn $1 | cut -d ':' -f3 | cut -d '(' -f1))
    __sum=$(echo "${__results[*]}"|sed "s/ /+/g")
    __count=${#__results[@]}
    echo " > $2: $(python -c "print($__sum/$__count.0)")"
}

process_framedrop "./native-10s-1080p30-framedrop"       "native 10 second 1080p 30 fps framedrop test, without subtitles"
process_framedrop "./native-10s-1080p60-framedrop"       "native 10 second 1080p 60 fps framedrop test, without subtitles"
process_framedrop "./native-10s-1080p90-framedrop"       "native 10 second 1080p 90 fps framedrop test, without subtitles"
process_framedrop "./native-10s-1080p120-framedrop"      "native 10 second 1080p 120 fps framedrop test, without subtitles"
process_framedrop "./mvee-10s-1080p30-framedrop"         "mvee 10 second 1080p 30 fps framedrop test, without subtitles"
process_framedrop "./mvee-10s-1080p60-framedrop"         "mvee 10 second 1080p 60 fps framedrop test, without subtitles"
process_framedrop "./mvee-10s-1080p90-framedrop"         "mvee 10 second 1080p 90 fps framedrop test, without subtitles"
process_framedrop "./mvee-10s-1080p120-framedrop"        "mvee 10 second 1080p 120 fps framedrop test, without subtitles"
process_framedrop "./native-10s-1080p30-framedrop-subs"  "native 10 second 1080p 30 fps framedrop test, with subtitles"
process_framedrop "./native-10s-1080p60-framedrop-subs"  "native 10 second 1080p 60 fps framedrop test, with subtitles"
process_framedrop "./native-10s-1080p90-framedrop-subs"  "native 10 second 1080p 90 fps framedrop test, with subtitles"
process_framedrop "./native-10s-1080p120-framedrop-subs" "native 10 second 1080p 120 fps framedrop test, with subtitles"
process_framedrop "./mvee-10s-1080p30-framedrop-subs"    "mvee 10 second 1080p 30 fps framedrop test, with subtitles"
process_framedrop "./mvee-10s-1080p60-framedrop-subs"    "mvee 10 second 1080p 60 fps framedrop test, with subtitles"
process_framedrop "./mvee-10s-1080p90-framedrop-subs"    "mvee 10 second 1080p 90 fps framedrop test, with subtitles"
process_framedrop "./mvee-10s-1080p120-framedrop-subs"   "mvee 10 second 1080p 120 fps framedrop test, with subtitles"
process_max_fps   "./native-10s-1080pwebm-maxfps"        "native 10 second 1080p webm max fps test, without subtitles"
process_max_fps   "./native-10s-1080pmp4-maxfps"         "native 10 second 1080p mp4 max fps test, without subtitles"
process_max_fps   "./native-10s-1440pwebm-maxfps"        "native 10 second 1440p webm max fps test, without subtitles"
process_max_fps   "./native-10s-1440pmp4-maxfps"         "native 10 second 1440p mp4 max fps test, without subtitles"
process_max_fps   "./mvee-10s-1080pwebm-maxfps"          "mvee 10 second 1080p webm max fps test, without subtitles"
process_max_fps   "./mvee-10s-1080pmp4-maxfps"           "mvee 10 second 1080p mp4 max fps test, without subtitles"
process_max_fps   "./mvee-10s-1440pwebm-maxfps"          "mvee 10 second 1440p webm max fps test, without subtitles"
process_max_fps   "./mvee-10s-1440pmp4-maxfps"           "mvee 10 second 1440p mp4 max fps test, without subtitles"
process_max_fps   "./native-10s-1080pwebm-maxfps-subs"   "native 10 second 1080p webm max fps test, with subtitles"
process_max_fps   "./native-10s-1080pmp4-maxfps-subs"    "native 10 second 1080p mp4 max fps test, with subtitles"
process_max_fps   "./native-10s-1440pwebm-maxfps-subs"   "native 10 second 1440p webm max fps test, with subtitles"
process_max_fps   "./native-10s-1440pmp4-maxfps-subs"    "native 10 second 1440p mp4 max fps test, with subtitles"
process_max_fps   "./mvee-10s-1080pwebm-maxfps-subs"     "mvee 10 second 1080p webm max fps test, with subtitles"
process_max_fps   "./mvee-10s-1080pmp4-maxfps-subs"      "mvee 10 second 1080p mp4 max fps test, with subtitles"
process_max_fps   "./mvee-10s-1440pwebm-maxfps-subs"     "mvee 10 second 1440p webm max fps test, with subtitles"
process_max_fps   "./mvee-10s-1440pmp4-maxfps-subs"      "mvee 10 second 1440p mp4 max fps test, with subtitles"