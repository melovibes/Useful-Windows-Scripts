<#
.SYNOPSIS
    Block-Distractions.ps1 - Block social media, live-shopping and adult sites via the Windows hosts file.

.DESCRIPTION
    Adds "0.0.0.0 domain" lines to C:\Windows\System32\drivers\etc\hosts inside a marked block:
        # >>> Block-Distractions START
        ...
        # <<< Block-Distractions END
    Reruns replace the block instead of duplicating it. Everything outside the block (your own
    entries, PowerToys Hosts File Editor entries) is left untouched. The block shows up in
    PowerToys Hosts File Editor like any other entries; avoid editing inside it there, because
    the next run of this script will overwrite it.

    Categories (switches):
      -Social    : Instagram, Facebook, TikTok, X/Twitter, Snapchat, Reddit, Pinterest, Threads,
                   Twitch, Kick, BeReal.
      -Shopping  : Whatnot, Fanatics Live, TikTok Shop, Popshop Live, NTWRK, CommentSold, Temu, Shein.
                   (eBay Live is part of ebay.com, so it isn't blocked.)
      -Adult     : built-in list of ~330 major adult sites. -AdultFromSource adds StevenBlack's
                   porn-only list (~77,000 entries):
                   https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts
                   (alternate: .../alternates/porn/hosts, which also includes ads/malware).
      -Security  : known malware, phishing, IP-logger, cryptojacking and scam domains.
                   -SecurityFromSource adds StevenBlack's unified ads+malware list (~74,000 entries):
                   https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
      -Proxies   : free VPNs, web proxies and anonymizers (Hola, StarVPN/starhome.io, Proton,
                   Windscribe, Hotspot Shield, hide.me, CroxyProxy, ProxySite, KProxy...) and
                   proxyware/bandwidth-sharing apps (Honeygain, Pawns/IPRoyal, PacketStream,
                   Peer2Profit, EarnApp, Repocket, Traffmonetizer, Grass). Tor Project is not blocked.
                   Proton: only protonvpn.com is blocked; proton.me (Proton Mail) is left alone.
      -Piracy    : torrent sites, cracked-software and fake repack sites (Pirate Bay, 1337x,
                   RARBG clones, YTS, FitGirl/DODI fakes, getintopc, crackingpatching...).
      -Gambling  : sportsbooks, DFS/pick'em, offshore books and pay-per-head sites, online and
                   sweepstakes casinos, prediction markets.
      -Streaming : Netflix, Hulu, Disney+, Max, Prime Video (primevideo.com only, not amazon.com),
                   Peacock, Paramount+, Tubi, Pluto, Crunchyroll, Sling, Fubo, Philo.
      -Gaming    : Steam, Epic, Roblox, Battle.net, EA, Riot, Xbox/cloud gaming, GeForce Now,
                   browser game sites, and Discord. NOTE: some teams use Discord for work.
      -Crypto    : exchanges and trading apps (Coinbase, Binance, Kraken, Crypto.com, Robinhood,
                   Webull, moomoo...), pump.fun, DexScreener and meme-coin launchpads.
      -YouTube   : blocks ALL of YouTube (hosts can't block only Shorts). Never included in -All
                   or -Company, because work training videos often live on YouTube.
      -Company   : preset = Social, Shopping, Adult, Security, Proxies, Piracy, Gambling,
                   Streaming, Gaming, Crypto. No YouTube, file sharing or webmail.
      -All       : every category except YouTube.
      -Custom    : extra domains, e.g. -Custom 'example.com','foo.net'.

    Protected allowlist: Microsoft/Windows Update/Office 365, Google Workspace (google.com,
    gmail.com, googleapis.com, gstatic.com), GitHub, Apple/iCloud, Dropbox, UniFi (ui.com,
    ubnt.com), Zoom, Slack, Cursor, Amazon/AWS, Cloudflare and certificate authorities are
    never blocked. A built-in or -Custom entry that hits the allowlist stops the script with
    no changes; matching entries from downloaded lists are skipped.

    Safety level : MEDIUM. It edits a system file, but only inside its own marked block.
                   Default is a DRY RUN that only prints counts. Nothing is written without -Apply.
                   A timestamped backup (hosts.bak-yyyyMMdd-HHmmss-fff) is saved next to hosts first.
                   The only network calls are the optional -AdultFromSource / -SecurityFromSource downloads.

    Admin        : -Apply and -Undo need an elevated PowerShell (Run as administrator).
                   Dry runs work without admin.

    IMPORTANT
      * DNS-over-HTTPS bypasses the hosts file. Turn it off for blocks to work:
          Chrome : Settings > Privacy and security > Security > "Use secure DNS" -> Off
          Edge   : Settings > Privacy, search, and services > Security > "Use secure DNS" -> Off
          Brave  : Settings > Privacy and security > Security > "Use secure DNS" -> Off
          Firefox: Settings > Privacy & Security > DNS over HTTPS -> Off
          Windows: Settings > Network & internet > (adapter) > DNS server assignment > DNS over HTTPS Off
      * A very large hosts file (e.g. -AdultFromSource and -SecurityFromSource, ~150k+ lines) can slow the Windows
        DNS Client service or cause brief lag on some systems. If browsing gets slow, rerun
        without -AdultFromSource, or use a DNS filter (e.g. Cloudflare 1.1.1.3 for families).
      * Apps and browsers cache DNS. The script runs "ipconfig /flushdns"; restart the browser too.

.EXAMPLE
    .\Block-Distractions.ps1 -All                         # dry run: shows what would be added
.EXAMPLE
    .\Block-Distractions.ps1 -Social -Shopping -Apply     # write the block (admin)
.EXAMPLE
    .\Block-Distractions.ps1 -Company -Apply                # workplace preset (admin)
.EXAMPLE
    .\Block-Distractions.ps1 -Adult -AdultFromSource -Security -SecurityFromSource -Apply
.EXAMPLE
    .\Block-Distractions.ps1 -Undo -Apply                 # remove the block (admin)

.NOTES
    Undo: run with -Undo -Apply, or restore a hosts.bak-* backup from the same folder.
    -HostsPath lets you test against a copy of a hosts file.
#>
[CmdletBinding()]
param(
    [switch]$Social,
    [switch]$Shopping,
    [switch]$Adult,
    [switch]$All,
    [switch]$YouTube,
    [switch]$AdultFromSource,
    [switch]$Security,
    [switch]$SecurityFromSource,
    [switch]$Proxies,
    [switch]$Piracy,
    [switch]$Gambling,
    [switch]$Streaming,
    [switch]$Gaming,
    [switch]$Crypto,
    [switch]$Company,
    [string[]]$Custom,
    [switch]$Apply,
    [switch]$Undo,
    [string]$HostsPath = "$env:windir\System32\drivers\etc\hosts"
)

$ErrorActionPreference = 'Stop'
$StartMarker = '# >>> Block-Distractions START'
$EndMarker   = '# <<< Block-Distractions END'
$SourceUrl   = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts'
$SecurityUrl = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'

# ---- Domain lists (bare domains; www. variants are added automatically) ----
$SocialDomains = @(
    'instagram.com', 'cdninstagram.com', 'instagr.am', 'ig.me', 'facebook.com', 'fb.com',
    'fbcdn.net', 'fbsbx.com', 'facebook.net', 'messenger.com', 'm.facebook.com', 'graph.facebook.com',
    'edge-chat.facebook.com', 'tiktok.com', 'tiktokv.com', 'tiktokcdn.com', 'tiktokcdn-us.com', 'tiktokv.us',
    'byteoversea.com', 'ibytedtos.com', 'ttwstatic.com', 'muscdn.com', 'musical.ly', 'vm.tiktok.com',
    'm.tiktok.com', 'x.com', 'twitter.com', 'twimg.com', 't.co', 'api.twitter.com',
    'api.x.com', 'abs.twimg.com', 'pbs.twimg.com', 'video.twimg.com', 'snapchat.com', 'snap.com',
    'snapkit.com', 'sc-cdn.net', 'snapchat.map.fastly.net', 'app.snapchat.com', 'reddit.com', 'redd.it',
    'redditmedia.com', 'redditstatic.com', 'redditinc.com', 'old.reddit.com', 'i.redd.it', 'v.redd.it',
    'preview.redd.it', 'pinterest.com', 'pinimg.com', 'pin.it', 'api.pinterest.com', 'threads.net',
    'threads.com', 'twitch.tv', 'twitchcdn.net', 'ttvnw.net', 'jtvnw.net', 'twitchsvc.net',
    'ext-twitch.tv', 'kick.com', 'files.kick.com', 'stream.kick.com', 'bere.al', 'bereal.com',
    'bereal.team'
)
$YouTubeDomains = @(
    'youtube.com', 'youtu.be', 'ytimg.com', 'googlevideo.com', 'youtube-nocookie.com',
    'm.youtube.com'
)
$ShoppingDomains = @(
    'whatnot.com', 'api.whatnot.com', 'images.whatnot.com', 'fanatics.live', 'api.fanatics.live', 'live.fanatics.com',
    'popshop.live', 'popshoplive.com', 'shop.tiktok.com', 'seller-us.tiktok.com', 'tiktokshop.com', 'ntwrk.com',
    'commentsold.com', 'temu.com', 'kwcdn.com', 'shein.com', 'ltwebstatic.com'
)
$AdultDomains = @(
    '1-porn.com', '12milf.com', '18tube.xxx', '1pornn.com', '1sexme.com', '1stube.com',
    '1xxx.net', '22cam.com', '24-xxx.com', '24lxxx.com', '24porn.com', '269sex.com',
    '26porn.com', '26porn.net', '29porn.com', '2cam.xxx', '2kcams.com', '33porn.com',
    '3am.xxx', '3d-sex.net', '3dsexx.net', '3dtube.xxx', '3dxxx.net', '3kcams.com',
    '3movs.xxx', '3rbxxx.com', '3sex.com', '3txxx.com', '3x-xxx.com', '4fcams.com',
    '4hdxxx.com', '4kporn.net', '4kporn.xxx', '4porn.com', '4porn4.com', '4sex4.com',
    '4sexy.net', '4tube.com', '505xxx.net', '5kporn.com', '7pcam.com', '7porn.net',
    '85porn.net', '85tube.com', '85tube.net', '88fuck.com', '8muses.xxx', '8porno.net',
    '8xxxhd.com', '91porn.com', '99cams.com', 'abxxx.com', 'ahsexo.com', 'allsex.xxx',
    'allx.xxx', 'anysex.com', 'anyxxx.com', 'aosex.com', 'aporne.com', 'argxxx.com',
    'asexon.com', 'atube.xxx', 'atubex.com', 'azfuck.com', 'aznude.com', 'babes.com',
    'bangbros.com', 'beeg.com', 'befuck.com', 'befuck.net', 'bifuck.com', 'bigxxx.net',
    'blacked.com', 'blogr.xxx', 'bongacams.com', 'booru.xxx', 'boycam.net', 'bqsex.com',
    'brazzers.com', 'broxxx.com', 'bysex.net', 'cam.com', 'cam4.com', 'cam69.com',
    'cam7.com', 'cam8.net', 'camabi.com', 'cambb.net', 'cambb.xxx', 'camdoz.com',
    'camera.com', 'cames4.com', 'camfz.com', 'camfz.net', 'camgo.com', 'camhax.com',
    'cams.com', 'camsoda.com', 'camwh.com', 'camz.com', 'chaturbate.com', 'clips4sale.com',
    'daftsex.com', 'digitalplayground.com', 'dmsex.net', 'dojki.xxx', 'dporn.com', 'drtuber.com',
    'dump.xxx', 'e621.net', 'ein.xxx', 'empflix.com', 'emsex.net', 'eporner.com',
    'evilangel.com', 'exxxn.com', 'fak.xxx', 'fansly.com', 'fpo.xxx', 'fux.com',
    'give.xxx', 'gjcam.com', 'hclips.com', 'hdhq.xxx', 'hdsex.xxx', 'hdv.xxx',
    'heavy-r.com', 'hentaihaven.xxx', 'here.xxx', 'homo.xxx', 'hqporner.com', 'htube.com',
    'htube.net', 'i18.xxx', 'icams.com', 'idxxx.net', 'img.xxx', 'imilf.net',
    'inxxx.com', 'ivr.xxx', 'ixxx.com', 'ixxx4.com', 'ixxx6.com', 'jizz.xxx',
    'josex.net', 'k9sex.com', 'kak.xxx', 'kink.com', 'kuxxx.com', 'leak.xxx',
    'livejasmin.com', 'ljcam.com', 'ljcam.net', 'manyvids.com', 'misex.net', 'mofos.com',
    'moms.xxx', 'motherless.com', 'msxxx.net', 'myfreecams.com', 'n-sex.net', 'naughtyamerica.com',
    'nhentai.net', 'nnn.xxx', 'nsfw.xxx', 'nude.com', 'nude4.com', 'nudez.com',
    'nur.xxx', 'nuvid.com', 'nxxx.com', 'ocxxx.com', 'ohsex.net', 'ok.xxx',
    'okxxx.net', 'omg.xxx', 'onlyfans.com', 'oosex.net', 'ooxxx.com', 'oxxxe.com',
    'phncdn.com', 'porn.com', 'porn.xxx', 'porn2.com', 'porn7.net', 'porn7.xxx',
    'porn8.com', 'porne.com', 'pornhub.com', 'pornhubpremium.com', 'pornj.com', 'pornl.com',
    'porno.com', 'pornone.com', 'pornq.com', 'porntrex.com', 'porntube.com', 'pornu.net',
    'pornv.xxx', 'pub.xxx', 'rat.xxx', 'rdtcdn.com', 'realitykings.com', 'red.xxx',
    'redtube.com', 'rexxx.com', 'rude.xxx', 'rule34.xxx', 'rxxxi.com', 's-xxx.com',
    'sb-cd.com', 'see.xxx', 'sex.com', 'sex.xxx', 'sex1x.com', 'sex3.com',
    'sex88.net', 'sexad.net', 'sexan.com', 'sexbq.com', 'sexei.net', 'sexf8.com',
    'sexfg.com', 'sexgr.net', 'sexhd.xxx', 'sexhq.com', 'sexix.net', 'sexiz.net',
    'sexjk.com', 'sexlo.net', 'sexm.xxx', 'sexng.com', 'sexo9.com', 'sexs.com',
    'sexs1.net', 'sextb.net', 'sextu.com', 'sextz.net', 'sexu.com', 'sexub.com',
    'sexy.com', 'sexy9.com', 'sos.xxx', 'spankbang.com', 'sqxxx.com', 'sss.xxx',
    'stripchat.com', 'sugar.xxx', 'sunporno.com', 'tape.xxx', 'thumbzilla.com', 'tnaflix.com',
    'tok.xxx', 'tophd.xxx', 'tporn.xxx', 'tube3.com', 'tube8.com', 'tubeq.xxx',
    'tushy.com', 'twink.xxx', 'twistys.com', 'txxx.com', 'txxxa.com', 'txxxi.com',
    'u-xxx.com', 'ucam.xxx', 'ujizz.xxx', 'vixen.com', 'vjxxx.com', 'vporn.com',
    'vrxxx.com', 'vxxx.com', 'vyxxx.com', 'way.xxx', 'woah.xxx', 'www.xxx',
    'x18.xxx', 'x6cam.com', 'xart.xxx', 'xcam.xxx', 'xcams.com', 'xcamy.com',
    'xhamster.com', 'xhamsterlive.com', 'xhcdn.com', 'xlx.xxx', 'xlxxx.com', 'xmilf.com',
    'xnxx-cdn.com', 'xnxx.com', 'xnxx.xxx', 'xnxxx.com', 'xtits.xxx', 'xtube.com',
    'xvideos-cdn.com', 'xvideos.com', 'xxx-4.com', 'xxx-5.com', 'xxx-r.com', 'xxx.com',
    'xxx.xxx', 'xxx0.net', 'xxx3.net', 'xxx8k.net', 'xxxa.com', 'xxxcj.com',
    'xxxde.net', 'xxxdl.net', 'xxxfm.com', 'xxxgr.net', 'xxxi.com', 'xxxn.com',
    'xxxnd.com', 'xxxo5.com', 'xxxoh.com', 'xxxuh.com', 'xxxx.com', 'xxxxn.net',
    'xxxxx.com', 'xxxzh.com', 'yasex.net', 'yes.xxx', 'youjizz.com', 'youporn.com',
    'youx.xxx', 'ypncdn.com', 'zsexx.com', 'zxxxa.com'
)

$SecurityDomains = @(
    'malware.wicar.org', 'testsafebrowsing.appspot.com', 'amtso.org', '2no.co', 'iplogger.org', 'iplogger.com',
    'grabify.link', 'blasze.tk', 'yip.su', 'ps3cfw.com', 'bmwforum.co', 'leancoding.co',
    'quickmessage.us', 'spottyfly.com', 'stopify.co', 'xn--yotu-1ra.be', 'lovebird.guru', 'trulove.guru',
    'dateing.club', 'otherhalf.life', 'shrekis.life', 'datasig.io', 'datauth.io', 'headshot.monster',
    'gaming-at-my.best', 'progaming.monster', 'yourmy.monster', 'screenshare.host', 'imageshare.best', 'screenshot.best',
    'gamingfun.me', 'catsnthing.com', 'joinmy.site', 'fortnitechat.site', 'fortnight.space', 'freegiftcards.co',
    'curiouscat.club', 'catsnthings.fun', 'xn--youtub-cze.com', 'bit-ly.co', 'coinhive.com', 'coin-hive.com',
    'authedmine.com', 'crypto-loot.com', 'cryptoloot.pro', 'jsecoin.com', 'minero.cc', 'webminepool.com',
    'ppoi.org', 'monerominer.rocks', '1ink.cc', 'adf.ly', 'linkvertise.com', 'ouo.io',
    'shrinkme.io', 'exe.io', 'sub2unlock.com', 'sub2unlock.net', 'boostellar.com', 'free-robux.com',
    'rbxgum.com', 'robuxday.com', 'freerobux.gg', 'claimrbx.gg', 'steamcommunlty.com', 'steamcommunity.ru',
    'steancommunity.com', 'stearncommunity.com', 'discord-nitro.gift', 'discordgift.site', 'dlscord.gift', 'discord-app.gift',
    'dlscordnitro.com', 'nitro-discord.org', 'paypal-login-secure.com', 'appleid-verify.com', 'amazon-security-alert.com', 'microsoft-support-alert.com',
    'windows-defender-alert.com'
)
$ProxyDomains = @(
    'hola.org', 'holavpn.net', 'h-vpn.org', 'hola.net', 'brightdata.com', 'luminati.io',
    'luminati-china.io', 'starvpn.com', 'starhome.io', 'protonvpn.com', 'windscribe.com',
    'windscribe.net', 'hotspotshield.com', 'hsselite.com', 'pango.co', 'anchorfree.com', 'betternet.co',
    'touchvpn.net', 'urban-vpn.com', 'urbanvpn.com', 'psiphon.ca', 'psiphon3.com', 'ultrasurf.us',
    'hide.me', 'hidester.com', 'hidemyass.com', 'croxyproxy.com', 'croxyproxy.rocks', 'croxyproxy.net',
    'proxysite.com', 'kproxy.com', 'hide.mn', 'proxyium.com', 'blockaway.net', '4everproxy.com',
    'proxfree.com', 'zalmos.com', 'vpnbook.com', 'freevpn.me', 'tunnelbear.com', 'hoxx.com',
    'browsec.com', 'zenmate.com', 'setupvpn.com', 'veepn.com', 'honeygain.com', 'honeygain.money',
    'pawns.app', 'iproyal.com', 'packetstream.io', 'peer2profit.com', 'peer2profit.app', 'earnapp.com',
    'brightvpn.com', 'repocket.co', 'repocket.com', 'traffmonetizer.com', 'getgrass.io', 'grass.io',
    'wynd.network', 'bitping.com', 'spider.dev', 'proxyrack.com', 'proxylite.ru', 'ebesucher.com'
)
$PiracyDomains = @(
    'thepiratebay.org', 'thepiratebay10.org', 'tpb.party', 'piratebay.live', 'pirateproxy.live', '1337x.to',
    '1337x.st', '1337x.ws', '1337x.eu', '1337x.se', '1337xx.to', 'x1337x.ws',
    'rarbg.to', 'rarbgmirror.com', 'rargb.to', 'rarbg.how', 'yts.mx', 'yts.am',
    'yts.lt', 'yts.rs', 'yts.do', 'eztv.re', 'eztvx.to', 'torrentgalaxy.to',
    'torrentgalaxy.mx', 'limetorrents.lol', 'limetorrents.info', 'torlock.com', 'torrentz2.eu', 'kickass.to',
    'kickasstorrents.to', 'katcr.to', 'nyaa.si', 'fitgirl-repacks.cc', 'fitgirl-repack.com', 'fitgirlrepacks.co',
    'fitgirl-repacks.xyz', 'dodi-repacks.site', 'dodi-repacks.download', 'dodirepacks.com', 'igg-games.com', 'skidrowreloaded.com',
    'skidrow-games.com', 'oceanofgames.com', 'steamunlocked.net', 'steamunlocked.org', 'steamrip.com', 'gog-games.to',
    'getintopc.com', 'igetintopc.com', 'get-into-pc.com', 'getintopc.us', 'crackingpatching.com', 'crackingpatching.unblockit.dev',
    'filecr.com', '4download.net', 'karanpc.com', 'softonic.com', 'haxpc.net', 'crackzsoft.me',
    'piratepc.me', 'cracksurl.com', 'kolompc.com', 'ftuapps.dev', 'procrackpc.co', 'plati.market',
    'sanet.st', 'softarchive.is', 'rutracker.org', 'rutor.info', 'nnmclub.to', 'zooqle.com',
    'magnetdl.com', 'bitsearch.to', 'glodls.to', 'idope.se', 'snowfl.com', 'btdig.com',
    'solidtorrents.to', 'fmovies.to', '123movies.to', 'soap2day.to', 'putlocker.vip'
)
$GamblingDomains = @(
    'draftkings.com', 'sportsbook.draftkings.com', 'casino.draftkings.com', 'dkn.gs', 'fanduel.com', 'sportsbook.fanduel.com',
    'casino.fanduel.com', 'betmgm.com', 'sports.betmgm.com', 'caesars.com', 'caesarssportsbook.com', 'williamhill.com',
    'espnbet.com', 'thescore.com', 'thescorebet.com', 'penn.com', 'barstoolsportsbook.com', 'betrivers.com',
    'rushstreetgaming.com', 'fanaticssportsbook.com', 'sportsbook.fanatics.com', 'betfanatics.com', 'prizepicks.com', 'underdogfantasy.com',
    'underdogsports.com', 'sleeper.com', 'dabble.com', 'chalkboard.io', 'stake.com', 'stake.us',
    'bovada.lv', 'bodog.eu', 'betonline.ag', 'mybookie.ag', 'betus.com.pa', 'sportsbetting.ag',
    'xbet.ag', 'everygame.eu', 'heritagesports.eu', 'betanysports.eu', 'bet365.com', 'pointsbet.com',
    'hardrock.bet', 'unibet.com', 'bwin.com', '888casino.com', '888sport.com', 'pokerstars.com',
    'pokerstars.net', 'wsop.com', 'ggpoker.com', 'acr.poker', 'ignitioncasino.eu', 'cafecasino.lv',
    'slotslv.com', 'wildcasino.ag', 'redstagcasino.eu', 'duckyluck.com', 'chumbacasino.com', 'luckylandslots.com',
    'globalpoker.com', 'pulsz.com', 'wowvegas.com', 'mcluck.com', 'fortunecoins.com', 'crowncoinscasino.com',
    'highfive.casino', 'funrize.com', 'zula.com', 'modo.us', 'rollingriches.com', 'realprize.com',
    'legendz.com', 'payperhead.com', 'payperhead247.com', 'realbookies.com', 'priceperplayer.com', 'aceperhead.com',
    'bwager.com', 'wagerweb.ag', 'kalshi.com', 'polymarket.com', 'novig.us'
)
$StreamingDomains = @(
    'netflix.com', 'netflix.net', 'nflxvideo.net', 'nflximg.net', 'nflximg.com', 'nflxext.com',
    'nflxso.net', 'hulu.com', 'hulustream.com', 'huluim.com', 'disneyplus.com', 'disney-plus.net',
    'bamgrid.com', 'dssott.com', 'max.com', 'hbomax.com', 'hbo.com', 'hbomaxcdn.com',
    'primevideo.com', 'aiv-cdn.net', 'aiv-delivery.net', 'peacocktv.com', 'peacock.com',
    'paramountplus.com', 'cbsivideo.com', 'pplusstatic.com', 'tubi.tv', 'tubitv.com', 'adrise.tv',
    'pluto.tv', 'plutotv.net', 'crunchyroll.com', 'vrv.co', 'sling.com', 'fubo.tv',
    'philo.com'
)
$GamingDomains = @(
    'steampowered.com', 'store.steampowered.com', 'steamcommunity.com', 'steamstatic.com', 'steamcontent.com', 'steamserver.net',
    'epicgames.com', 'epicgames.dev', 'unrealengine.com', 'fortnite.com', 'roblox.com', 'rbxcdn.com',
    'roblox.cn', 'rbx.com', 'battle.net', 'blizzard.com', 'blzstatic.cn', 'ea.com',
    'origin.com', 'eaplay.com', 'riotgames.com', 'leagueoflegends.com', 'playvalorant.com', 'riotcdn.net',
    'xbox.com', 'xboxlive.com', 'xbox.gg', 'play.geforcenow.com', 'geforcenow.com', 'nvidiagrid.net',
    'miniclip.com', 'poki.com', 'poki-cdn.com', 'crazygames.com', 'coolmathgames.com', 'friv.com',
    'y8.com', 'kongregate.com', 'armorgames.com', 'chess.com', 'lichess.org', 'itch.io',
    'gog.com', 'ubisoft.com', 'ubi.com', 'playstation.com', 'twitchtracker.com', 'discord.com',
    'discord.gg', 'discordapp.com', 'discordapp.net', 'discord.media'
)
$CryptoDomains = @(
    'coinbase.com', 'coinbase.org', 'binance.com', 'binance.us', 'bnbstatic.com', 'kraken.com',
    'crypto.com', 'robinhood.com', 'webull.com', 'moomoo.com', 'futunn.com', 'pump.fun',
    'dexscreener.com', 'dextools.io', 'birdeye.so', 'gmgn.ai', 'photon-sol.tinyastro.io', 'bullx.io',
    'raydium.io', 'jup.ag', 'letsbonk.fun', 'moonshot.com', 'sunpump.meme', 'four.meme',
    'uniswap.org', 'pancakeswap.finance', 'gemini.com', 'kucoin.com', 'bybit.com', 'okx.com',
    'mexc.com', 'gate.io', 'gate.com', 'htx.com', 'bitget.com', 'bitstamp.net',
    'coinmarketcap.com', 'coingecko.com', 'metamask.io', 'phantom.app', 'opensea.io', 'blur.io'
)

# Critical domains that must never be blocked (exact match or any subdomain). The script refuses
# to write if a built-in or -Custom entry hits one of these; source lists are filtered instead.
$AllowList = @(
    'microsoft.com', 'windowsupdate.com', 'windows.com', 'windows.net', 'live.com', 'office.com', 'office.net',
    'office365.com', 'microsoftonline.com', 'sharepoint.com', 'outlook.com', 'msftconnecttest.com', 'azure.com',
    'google.com', 'googleapis.com', 'gstatic.com', 'gmail.com', 'googleusercontent.com', 'gvt1.com',
    'github.com', 'githubusercontent.com', 'apple.com', 'icloud.com', 'dropbox.com', 'dropboxapi.com',
    'ui.com', 'ubnt.com', 'zoom.us', 'slack.com', 'cursor.com', 'amazon.com', 'amazonaws.com', 'cloudflare.com',
    'digicert.com', 'letsencrypt.org', 'akamaihd.net'
)

function Expand-Www([string[]]$Domains) {
    foreach ($d in $Domains) {
        $d = $d.Trim().ToLower()
        if (-not $d) { continue }
        $d
        if (($d.Split('.').Count -eq 2) -or ($d -match '\.(co|com)\.\w\w$' -and $d.Split('.').Count -eq 3)) { "www.$d" }
    }
}

function Get-SourceDomains([string]$Url) {
    Write-Host "[*] Downloading $Url ..." -ForegroundColor Cyan
    try {
        $raw = (Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 60).Content
    } catch {
        Write-Warning "Download failed ($($_.Exception.Message)). Using built-in list only."
        return @()
    }
    foreach ($line in ($raw -split "`r?`n")) {
        if ($line -match '^0\.0\.0\.0\s+([^\s#]+)') {
            $h = $Matches[1].ToLower()
            if ($h -ne '0.0.0.0' -and $h -ne 'localhost') { $h }
        }
    }
}

function Remove-Block([string[]]$Lines) {
    # Returns the lines with any previous Block-Distractions block removed.
    $out = New-Object System.Collections.Generic.List[string]
    $inside = $false
    foreach ($l in $Lines) {
        if ($l.Trim() -eq $StartMarker) { $inside = $true; continue }
        if ($inside -and $l.Trim() -eq $EndMarker) { $inside = $false; continue }
        if (-not $inside) { $out.Add($l) }
    }
    if ($inside) { throw "Found '$StartMarker' without '$EndMarker'. Fix the hosts file by hand (or restore a backup) before rerunning." }
    # trim trailing blank lines left behind
    while ($out.Count -gt 0 -and [string]::IsNullOrWhiteSpace($out[$out.Count - 1])) { $out.RemoveAt($out.Count - 1) }
    return ,$out.ToArray()
}

# ---- Admin check (only when writing to the real system hosts file) ----
$sysHosts = "$env:windir\System32\drivers\etc\hosts"
$isSystemFile = $IsWindows -ne $false -and ([IO.Path]::GetFullPath($HostsPath) -ieq [IO.Path]::GetFullPath($sysHosts))
if ($Apply -and $isSystemFile) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) {
        Write-Host "[!] Administrator rights required to change the hosts file." -ForegroundColor Red
        Write-Host "    Right-click PowerShell > 'Run as administrator', then rerun this command." -ForegroundColor Red
        exit 1
    }
}

if (-not (Test-Path -LiteralPath $HostsPath)) { throw "Hosts file not found: $HostsPath" }
$current = @(Get-Content -LiteralPath $HostsPath)
$base = Remove-Block $current
$hadBlock = ($current.Count -ne $base.Count) -or ($current -contains $StartMarker)

if ($Undo) {
    if (-not $hadBlock) { Write-Host "[=] No Block-Distractions block found. Nothing to undo." -ForegroundColor Green; exit 0 }
    $newLines = $base
    $summary = "Remove existing Block-Distractions block ($($current.Count - $base.Count) lines)."
} else {
    if ($All -or $Company) {
        $Social = $Shopping = $Adult = $Security = $Proxies = $Piracy = $Gambling = $Streaming = $Gaming = $Crypto = $true
    }
    if (-not ($Social -or $Shopping -or $Adult -or $YouTube -or $Security -or $Proxies -or $Piracy -or
              $Gambling -or $Streaming -or $Gaming -or $Crypto -or $Custom)) {
        Write-Host "Pick at least one category (see header), -Company, -All or -Custom. Use -Undo to remove the block." -ForegroundColor Yellow
        exit 1
    }
    $sections = [ordered]@{}
    if ($Social)    { $sections['Social']    = @(Expand-Www $SocialDomains) }
    if ($Shopping)  { $sections['Shopping']  = @(Expand-Www $ShoppingDomains) }
    if ($Security)  {
        $sec = @(Expand-Www $SecurityDomains)
        if ($SecurityFromSource) { $sec += @(Get-SourceDomains $SecurityUrl) }
        $sections['Security'] = $sec
    }
    if ($Proxies)   { $sections['Proxies']   = @(Expand-Www $ProxyDomains) }
    if ($Piracy)    { $sections['Piracy']    = @(Expand-Www $PiracyDomains) }
    if ($Gambling)  { $sections['Gambling']  = @(Expand-Www $GamblingDomains) }
    if ($Streaming) { $sections['Streaming'] = @(Expand-Www $StreamingDomains) }
    if ($Gaming)    { $sections['Gaming']    = @(Expand-Www $GamingDomains) }
    if ($Crypto)    { $sections['Crypto']    = @(Expand-Www $CryptoDomains) }
    # Full YouTube only when explicitly asked for (-YouTube), never via -All / -Company.
    if ($YouTube -and -not $Company) { $sections['YouTube'] = @(Expand-Www $YouTubeDomains) }
    elseif ($YouTube -and $Company)  { Write-Host "[i] -Company never blocks YouTube; ignoring -YouTube." -ForegroundColor Yellow }
    if ($Custom)    { $sections['Custom']    = @(Expand-Www ($Custom -split '[,;\s]+')) }
    if ($Adult) {
        $a = @(Expand-Www $AdultDomains)
        if ($AdultFromSource) { $a += @(Get-SourceDomains $SourceUrl) }
        $sections['Adult'] = $a
    }

    # ---- Allowlist safety check ----
    $sourceSections = @()
    if ($AdultFromSource) { $sourceSections += 'Adult' }
    if ($SecurityFromSource) { $sourceSections += 'Security' }
    $builtInSets = @{ Adult = $AdultDomains; Security = $SecurityDomains }
    $filteredFromSource = 0
    foreach ($name in @($sections.Keys)) {
        $keep = New-Object System.Collections.Generic.List[string]
        foreach ($d in $sections[$name]) {
            $hit = $AllowList | Where-Object { $d -eq $_ -or $d.EndsWith(".$_") } | Select-Object -First 1
            if (-not $hit) { $keep.Add($d); continue }
            $fromBuiltIn = ($name -ne 'Custom') -and -not (($sourceSections -contains $name) -and
                           -not ((Expand-Www $builtInSets[$name]) -contains $d))
            if ($name -eq 'Custom' -or $fromBuiltIn) {
                Write-Host "[!] Refusing to block '$d' ($name): it matches protected domain '$hit'." -ForegroundColor Red
                Write-Host "    Critical services (Microsoft, Google, GitHub, Apple, Dropbox, UniFi, Zoom, Slack...) are never blocked. Nothing was changed." -ForegroundColor Red
                exit 2
            }
            $filteredFromSource++
        }
        $sections[$name] = $keep.ToArray()
    }
    if ($filteredFromSource) { Write-Host "[i] Skipped $filteredFromSource downloaded entries that match the protected allowlist." -ForegroundColor Cyan }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $block = New-Object System.Collections.Generic.List[string]
    $block.Add($StartMarker)
    $block.Add("# Added by Block-Distractions.ps1 on $(Get-Date -Format 'yyyy-MM-dd HH:mm'). Rerun the script to update; -Undo -Apply to remove.")
    $counts = [ordered]@{}
    foreach ($name in $sections.Keys) {
        $block.Add("# --- $name ---")
        $n = 0
        foreach ($d in $sections[$name]) { if ($seen.Add($d)) { $block.Add("0.0.0.0 $d"); $n++ } }
        $counts[$name] = $n
    }
    $block.Add($EndMarker)

    $newLines = @($base) + @('') + $block.ToArray()
    $summary = ($counts.Keys | ForEach-Object { "{0}: {1}" -f $_, $counts[$_] }) -join ', '
    $summary = "Block with $($seen.Count) entries ($summary)." + $(if ($hadBlock) { ' Replaces the existing block.' } else { '' })
}

if (-not $Apply) {
    Write-Host "[DRY RUN] $summary" -ForegroundColor Yellow
    Write-Host "          Target: $HostsPath. Nothing was changed. Add -Apply to write it." -ForegroundColor Yellow
    exit 0
}

$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
$backup = "$HostsPath.bak-$stamp"
$i = 1
while (Test-Path -LiteralPath $backup) { $backup = "$HostsPath.bak-$stamp-$i"; $i++ }
Copy-Item -LiteralPath $HostsPath -Destination $backup
Write-Host "[+] Backup saved: $backup" -ForegroundColor Green

# ASCII without BOM keeps the hosts file readable by Windows and PowerToys Hosts File Editor.
[IO.File]::WriteAllLines($HostsPath, [string[]]$newLines, (New-Object System.Text.ASCIIEncoding))
Write-Host "[+] $summary" -ForegroundColor Green

if ($isSystemFile) {
    & ipconfig /flushdns | Out-Null
    Write-Host "[+] DNS cache flushed. Restart your browser for changes to take effect." -ForegroundColor Green
    Write-Host "[i] Turn off 'Secure DNS' / DNS-over-HTTPS in your browser or it will skip the hosts file (see header)." -ForegroundColor Cyan
}
