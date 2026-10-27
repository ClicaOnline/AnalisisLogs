<#
  analizar_logs.ps1
  Preprocesa logs de Apache/Nginx (formato combined, p.ej. Plesk access_ssl_log)
  y error_log de Apache/ModSecurity. Genera CSVs listos para Excel (separador ;
  UTF-8 con BOM) con:
    - cardinalidad de visitantes humanos por dia y hora (comparable con GA4)
    - ranking de visitantes/IPs/subredes con puntuacion de posible scraping
    - inventario de user agents y bots
  Compatible con Windows PowerShell 5.1 y PowerShell 7. Sin dependencias.

  Uso:  arrastrar ficheros o carpetas sobre analizar_logs.bat
        o: powershell -ExecutionPolicy Bypass -File analizar_logs.ps1 <ruta> [<ruta>...] [-Seudonimizar] [-SinDetalle]
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$Seudonimizar,
    [switch]$SinDetalle,
    [string]$Salida,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rutas
)

$ErrorActionPreference = 'Stop'
$es = [System.Globalization.CultureInfo]::GetCultureInfo('es-ES')
$utf8Bom = New-Object System.Text.UTF8Encoding $true
$MAX_FILAS_EXCEL = 1000000

# ---------------------------------------------------------------- utilidades
function Csv([string]$s) {
    if ($null -eq $s) { return '""' }
    $s = $s -replace '[\r\n\t]', ' '
    # Evita inyeccion de formulas en Excel (UA o URLs maliciosas que empiezan por = + @ -)
    if ($s.Length -gt 1 -and '=+-@'.IndexOf($s[0]) -ge 0) { $s = "'" + $s }
    elseif ($s.Length -eq 1 -and '=+@'.IndexOf($s[0]) -ge 0) { $s = "'" + $s }
    return '"' + $s.Replace('"', '""') + '"'
}
function Dec([double]$d) { return $d.ToString('0.0', $es) }

function Abrir-Lector([string]$ruta) {
    $fs = [System.IO.File]::Open($ruta, 'Open', 'Read', 'ReadWrite')
    if ($ruta -match '\.gz$') {
        $gz = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
        return New-Object System.IO.StreamReader($gz, [System.Text.Encoding]::UTF8)
    }
    return New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)
}

function Nuevo-Escritor([string]$ruta, [string]$cabecera) {
    $w = New-Object System.IO.StreamWriter($ruta, $false, $utf8Bom)
    $w.WriteLine($cabecera)
    return $w
}

$sha = [System.Security.Cryptography.SHA256]::Create()
$sal = [guid]::NewGuid().ToString()
$cacheSeud = @{}
function Seud([string]$valor, [string]$prefijo) {
    if (-not $Seudonimizar) { return $valor }
    $k = $prefijo + $valor
    if ($cacheSeud.ContainsKey($k)) { return $cacheSeud[$k] }
    $b = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sal + $k))
    $h = $prefijo + ([System.BitConverter]::ToString($b, 0, 6).Replace('-', '').ToLower())
    $cacheSeud[$k] = $h
    return $h
}

function Subred([string]$ip) {
    if ($ip.Contains('.')) {
        $i = $ip.LastIndexOf('.')
        return $ip.Substring(0, $i) + '.0/24'
    }
    $p = $ip.Split(':')
    if ($p.Length -ge 4) { return ($p[0..3] -join ':') + '::/64' }
    return $ip
}

$meses = @{ Jan = '01'; Feb = '02'; Mar = '03'; Apr = '04'; May = '05'; Jun = '06'; Jul = '07'; Aug = '08'; Sep = '09'; Oct = '10'; Nov = '11'; Dec = '12' }

# ---------------------------------------------------- clasificacion user agents
# Orden importa: la primera coincidencia gana. [patron, nombre, tipo]
$firmas = @(
    @('Googlebot|Google-InspectionTool|GoogleOther|AdsBot-Google|Mediapartners-Google|Storebot-Google', 'Google', 'bot_buscador'),
    @('bingbot|BingPreview|msnbot|adidxbot', 'Bing', 'bot_buscador'),
    @('YandexBot|YandexImages', 'Yandex', 'bot_buscador'),
    @('DuckDuckBot|DuckAssistBot', 'DuckDuckGo', 'bot_buscador'),
    @('Baiduspider', 'Baidu', 'bot_buscador'),
    @('Applebot', 'Apple', 'bot_buscador'),
    @('Qwantbot|Qwantify', 'Qwant', 'bot_buscador'),
    @('GPTBot|ChatGPT-User|OAI-SearchBot', 'OpenAI', 'bot_ia'),
    @('ClaudeBot|Claude-User|Claude-SearchBot|anthropic-ai', 'Anthropic', 'bot_ia'),
    @('PerplexityBot|Perplexity-User', 'Perplexity', 'bot_ia'),
    @('CCBot', 'CommonCrawl', 'bot_ia'),
    @('Bytespider|TikTokSpider', 'ByteDance', 'bot_ia'),
    @('Amazonbot', 'Amazon', 'bot_ia'),
    @('meta-externalagent|meta-externalfetcher|FacebookBot', 'Meta IA', 'bot_ia'),
    @('cohere-ai|Diffbot|YouBot|MistralAI|AI2Bot|Timpibot|ImagesiftBot|omgili', 'IA otros', 'bot_ia'),
    @('AhrefsBot|AhrefsSiteAudit', 'Ahrefs', 'bot_seo'),
    @('SemrushBot|SiteAuditBot', 'Semrush', 'bot_seo'),
    @('MJ12bot', 'Majestic', 'bot_seo'),
    @('DotBot|rogerbot', 'Moz', 'bot_seo'),
    @('Screaming Frog', 'Screaming Frog', 'bot_seo'),
    @('SEOJuice', 'SEOJuice', 'bot_seo'),
    @('BLEXBot|DataForSeoBot|serpstatbot|SeekportBot|Barkrowler|MegaIndex|SEOkicks|Sitebulb', 'SEO otros', 'bot_seo'),
    @('facebookexternalhit|facebookcatalog', 'Facebook preview', 'bot_social'),
    @('Twitterbot|LinkedInBot|WhatsApp|TelegramBot|Slackbot|Discordbot|Pinterest|redditbot|SkypeUriPreview', 'Preview social', 'bot_social'),
    @('Jetpack|WordPress\.com|WordPress/', 'WordPress/Jetpack', 'servicio'),
    @('Plesk', 'Plesk', 'servicio'),
    @('UptimeRobot|Pingdom|StatusCake|Site24x7|BetterUptime|Uptime-Kuma|monitis|HetrixTools|Better Stack', 'Monitorizacion', 'servicio'),
    @('Chrome-Lighthouse|PageSpeed|GTmetrix', 'Rendimiento', 'servicio'),
    @('HeadlessChrome|PhantomJS|Puppeteer|Playwright|Selenium|electron', 'Navegador headless', 'herramienta'),
    @('python-requests|python-urllib|aiohttp|httpx|Scrapy|python/', 'Python', 'herramienta'),
    @('curl/|Wget|libwww-perl|LWP::', 'curl/wget', 'herramienta'),
    @('Go-http-client|okhttp|Java/|Apache-HttpClient|axios|node-fetch|undici|got \(|Ruby|PHP/|GuzzleHttp|Postman|Insomnia|HTTPie|zgrab|masscan|Nmap|Nuclei|sqlmap|Nikto|WPScan', 'Cliente HTTP / escaner', 'herramienta'),
    @('bot|crawl|spider|slurp|scan|fetch|archiver|scraper', 'Bot otro', 'bot_otro')
)
$firmasRx = foreach ($f in $firmas) { , @((New-Object regex($f[0], 'IgnoreCase, Compiled')), $f[1], $f[2]) }
$navegadorRx = New-Object regex('Mozilla/5\.0 \((Windows|Macintosh|X11|Linux|iPhone|iPad|Android)', 'Compiled')
$cacheUa = @{}
function Clasificar-Ua([string]$ua) {
    if ($cacheUa.ContainsKey($ua)) { return $cacheUa[$ua] }
    $r = $null
    if ($ua -eq '-' -or $ua.Trim() -eq '') { $r = @('Sin user agent', 'herramienta') }
    else {
        foreach ($f in $firmasRx) { if ($f[0].IsMatch($ua)) { $r = @($f[1], $f[2]); break } }
        if ($null -eq $r) {
            if ($navegadorRx.IsMatch($ua)) { $r = @('', 'humano') } else { $r = @('UA no estandar', 'herramienta') }
        }
    }
    $cacheUa[$ua] = $r
    return $r
}

# --------------------------------------------------- clasificacion de rutas
$rxRecurso = New-Object regex('\.(css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot)$', 'IgnoreCase, Compiled')
$rxOtro = New-Object regex('\.(xml|txt|json|pdf|zip|rar|gz|mp4|webm|mp3|wav|docx?|xlsx?|pptx?|csv)$', 'IgnoreCase, Compiled')
$rxTecnico = New-Object regex('^/(wp-admin/|wp-json|wp-cron\.php|xmlrpc\.php|wp-login\.php|wp-content/|wp-includes/|feed/?$|.*/feed/?$|\?rest_route|cgi-bin|\.well-known/)', 'IgnoreCase, Compiled')
$rxSensible = New-Object regex('wp-login\.php|xmlrpc\.php|/\.env|/\.git|wp-config|phpmyadmin|pma/|\.sql$|\.bak$|\.old$|/vendor/phpunit|eval-stdin|/\.aws|/server-status|/actuator|/boaform|/HNAP1|/setup\.php|/shell|/wp-content/plugins/.*/readme\.txt|/\.DS_Store|/backup|/config\.(php|json|yml)|/install\.php|/administrator/|/owa/|/ecp/', 'IgnoreCase, Compiled')

# -------------------------------------------------------------- estructuras
class Visitante {
    [int]$Id; [string]$Ip; [string]$Ua; [string]$Bot; [string]$Tipo
    [string]$Primera; [string]$Ultima
    [int]$Peticiones; [int]$Paginas; [int]$Recursos; [int]$E4; [int]$E404; [int]$E5
    [int]$Robots; [int]$Sensibles; [int]$PaginasConReferer; [long]$Bytes
    [string]$MinActual; [int]$CuentaMin; [int]$MaxPagMin
    [System.Collections.Generic.HashSet[string]]$Urls
    [int]$Score; [string]$Motivos; [string]$Nivel
    [string]$CsvIni; [string]$CsvFin
}
class Agregado {
    [int]$Peticiones; [int]$Paginas; [int]$PvHumanas; [int]$PetBots; [int]$E4; [int]$E5; [long]$Bytes
    [System.Collections.Generic.HashSet[string]]$Ips
    [System.Collections.Generic.HashSet[string]]$IpsHumanas
    [System.Collections.Generic.HashSet[string]]$IpsBots
    [System.Collections.Generic.Dictionary[int, int]]$VisHumanos  # id visitante -> paginas vistas
    Agregado() {
        $this.Ips = New-Object 'System.Collections.Generic.HashSet[string]'
        $this.IpsHumanas = New-Object 'System.Collections.Generic.HashSet[string]'
        $this.IpsBots = New-Object 'System.Collections.Generic.HashSet[string]'
        $this.VisHumanos = New-Object 'System.Collections.Generic.Dictionary[int,int]'
    }
    [void] Sumar([string]$ip, [int]$id, [long]$by, [bool]$esPag, [bool]$esBot, [bool]$e4, [bool]$e5) {
        $this.Peticiones++; $this.Bytes += $by
        [void]$this.Ips.Add($ip)
        if ($esPag) { $this.Paginas++ }
        if ($esBot) { $this.PetBots++; [void]$this.IpsBots.Add($ip) }
        else {
            [void]$this.IpsHumanas.Add($ip)
            if ($esPag) {
                $this.PvHumanas++
                $n = 0
                if ($this.VisHumanos.TryGetValue($id, [ref]$n)) { $this.VisHumanos[$id] = $n + 1 } else { $this.VisHumanos[$id] = 1 }
            }
        }
        if ($e4) { $this.E4++ } elseif ($e5) { $this.E5++ }
    }
}
class Util {
    static [string] Q([string]$s) {
        if ($s.Length -gt 1 -and '=+-@'.IndexOf($s[0]) -ge 0) { $s = "'" + $s }
        if ($s.IndexOf([char]34) -ge 0) { $s = $s.Replace('"', '""') }
        return '"' + $s + '"'
    }
    static [string] Linea([string]$fecha, [string]$hora, [string]$ini, [string]$met, [string]$ruta, [string]$query, [int]$st, [long]$by, [string]$ref, [string]$fin, [string]$tr) {
        return $fecha + ';' + $hora + ';' + $fecha + ' ' + $hora + ';' + $ini + ';' + $met + ';' + [Util]::Q($ruta) + ';' + [Util]::Q($query) + ';' + $st + ';' + $by + ';' + [Util]::Q($ref) + ';' + $fin + ';' + $tr
    }
}

$visitantes = New-Object 'System.Collections.Generic.Dictionary[string,object]'
$porDia = New-Object 'System.Collections.Generic.SortedDictionary[string,object]'
$porHora = New-Object 'System.Collections.Generic.SortedDictionary[string,object]'
$wafPorIp = @{}

# ------------------------------------------------------------ ficheros entrada
if (-not $Rutas -or $Rutas.Count -eq 0) {
    Write-Host 'Uso: arrastra uno o varios logs (o una carpeta) sobre analizar_logs.bat' -ForegroundColor Yellow
    exit 1
}
$ficheros = @()
foreach ($r in $Rutas) {
    if (Test-Path -LiteralPath $r -PathType Container) {
        $ficheros += Get-ChildItem -LiteralPath $r -File | Where-Object { $_.Name -match 'log' -and $_.Name -notmatch '\.webstat$' -and $_.Name -notmatch '\.(csv|txt|zip)$' }
    } elseif (Test-Path -LiteralPath $r -PathType Leaf) {
        $ficheros += Get-Item -LiteralPath $r
    } else { Write-Host "No existe: $r" -ForegroundColor Yellow }
}
$ficheros = @($ficheros | Where-Object { $_.Length -gt 0 })
$logsError = @($ficheros | Where-Object { $_.Name -match 'error' } | Sort-Object LastWriteTime)
$logsAcceso = @($ficheros | Where-Object { $_.Name -notmatch 'error' -and $_.Name -notmatch '\.webstat$' } | Sort-Object LastWriteTime)
$omitidos = @($ficheros | Where-Object { $_.Name -match '\.webstat$' })
if ($omitidos.Count -gt 0) { Write-Host "Omitidos .webstat (son copia del log, duplicarian datos): $($omitidos.Name -join ', ')" -ForegroundColor DarkYellow }
if ($logsAcceso.Count -eq 0 -and $logsError.Count -eq 0) { Write-Host 'No hay ficheros con contenido.' -ForegroundColor Yellow; exit 1 }

if (-not $Salida) {
    $base = if ($ficheros.Count -gt 0) { $ficheros[0].DirectoryName } else { (Get-Location).Path }
    $Salida = Join-Path $base ('analisis_logs_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
New-Item -ItemType Directory -Force -Path $Salida | Out-Null
$reloj = [System.Diagnostics.Stopwatch]::StartNew()

# -------------------------------------------------------------- error_log
$rxErr = New-Object regex('^\[(?<f>[^\]]+)\] \[(?<mod>[^:\]]+):(?<niv>[^\]]+)\](?: \[pid [^\]]+\])?(?: \[client (?<ip>[^\]]+)\])? ?(?<msg>.*)$', 'Compiled')
$rxId = New-Object regex('\[id "(?<v>[^"]*)"\]', 'Compiled')
$rxMsg = New-Object regex('\[msg "(?<v>[^"]*)"\]', 'Compiled')
$rxUri = New-Object regex('\[uri "(?<v>[^"]*)"\]', 'Compiled')
$lineasErr = 0
if ($logsError.Count -gt 0) {
    $wE = Nuevo-Escritor (Join-Path $Salida '08_errores_servidor.csv') 'fecha;hora;fecha_hora;modulo;nivel;ip;uri;regla_id;mensaje'
    foreach ($f in $logsError) {
        Write-Host "Leyendo error log: $($f.Name)" -ForegroundColor Cyan
        $lr = Abrir-Lector $f.FullName
        while ($null -ne ($l = $lr.ReadLine())) {
            $m = $rxErr.Match($l)
            if (-not $m.Success) { continue }
            $lineasErr++
            # "Thu Sep 10 08:10:14.201387 2026"
            $p = $m.Groups['f'].Value.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
            $fecha = ''; $hora = ''
            if ($p.Length -ge 5 -and $meses.ContainsKey($p[1])) {
                $fecha = '{0}-{1}-{2:00}' -f $p[4], $meses[$p[1]], [int]$p[2]
                $hora = $p[3].Substring(0, [Math]::Min(8, $p[3].Length))
            }
            $ip = $m.Groups['ip'].Value
            if ($ip.Contains('.') -and $ip.Contains(':')) { $ip = $ip.Substring(0, $ip.LastIndexOf(':')) }
            $mod = $m.Groups['mod'].Value; $msg = $m.Groups['msg'].Value
            $uri = ''; $id = ''
            if ($mod -eq 'security2') {
                $id = $rxId.Match($msg).Groups['v'].Value
                $uri = $rxUri.Match($msg).Groups['v'].Value
                $mm = $rxMsg.Match($msg).Groups['v'].Value
                if ($mm) { $msg = $mm.Split('|')[0] }
                if ($ip) { if ($wafPorIp.ContainsKey($ip)) { $wafPorIp[$ip]++ } else { $wafPorIp[$ip] = 1 } }
            } else {
                $msg = ($msg -replace ', referer: .*$', '')
                if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
            }
            $wE.WriteLine(($fecha, $hora, (Csv "$fecha $hora"), (Csv $mod), (Csv $m.Groups['niv'].Value), (Csv (Seud $ip 'ip_')), (Csv $uri), (Csv $id), (Csv $msg)) -join ';')
        }
        $lr.Close()
    }
    $wE.Close()
}

# -------------------------------------------------------------- access log
$rxAcc = New-Object regex('^(?<ip>\S+) \S+ \S+ \[(?<dt>[^\]]+)\] "(?<req>(?:[^"\\]|\\.)*)" (?<st>\d{3}) (?<by>\S+)(?: "(?<ref>(?:[^"\\]|\\.)*)" "(?<ua>(?:[^"\\]|\\.)*)")?', 'Compiled')
$cabDet = 'fecha;hora;fecha_hora;ip;subred;visitante_id;metodo;ruta;query;estado;bytes;referer;user_agent;tipo_trafico;bot;tipo_recurso'
$wD = $null; $parte = 1; $filasParte = 0
if (-not $SinDetalle -and $logsAcceso.Count -gt 0) { $wD = Nuevo-Escritor (Join-Path $Salida '01_peticiones.csv') $cabDet }
$total = 0; $malformadas = 0; $sigId = 0; $kDia = $null; $kHora = $null; $aDia = $null; $aHora = $null

foreach ($f in $logsAcceso) {
    Write-Host "Leyendo access log: $($f.Name) ($([Math]::Round($f.Length / 1MB, 1)) MB)" -ForegroundColor Cyan
    $lr = Abrir-Lector $f.FullName
    while ($null -ne ($l = $lr.ReadLine())) {
        $m = $rxAcc.Match($l)
        if (-not $m.Success) { $malformadas++; continue }
        $total++
        if ($total % 100000 -eq 0) { Write-Host ("  {0:N0} lineas... ({1:N0} s)" -f $total, $reloj.Elapsed.TotalSeconds) }

        $ip = $m.Groups['ip'].Value
        $dt = $m.Groups['dt'].Value   # 27/Oct/2026:08:03:53 +0100
        $fecha = $dt.Substring(7, 4) + '-' + $meses[$dt.Substring(3, 3)] + '-' + $dt.Substring(0, 2)
        $hora = $dt.Substring(12, 8)
        $fh = $fecha + ' ' + $hora
        $req = $m.Groups['req'].Value.Split(' ')
        $metodo = $req[0]
        $url = if ($req.Length -ge 2) { $req[1] } else { '' }
        $qi = $url.IndexOf('?')
        if ($qi -ge 0) { $ruta = $url.Substring(0, $qi); $query = $url.Substring($qi + 1) } else { $ruta = $url; $query = '' }
        $st = [int]$m.Groups['st'].Value
        $by = 0L; [void][long]::TryParse($m.Groups['by'].Value, [ref]$by)
        $ref = $m.Groups['ref'].Value
        $ua = if ($m.Groups['ua'].Success) { $m.Groups['ua'].Value } else { '-' }

        if ($rxRecurso.IsMatch($ruta)) { $tr = 'recurso' }
        elseif ($rxTecnico.IsMatch($ruta) -or $rxOtro.IsMatch($ruta)) { $tr = 'otro' }
        elseif ($metodo -eq 'GET' -and (($st -ge 200 -and $st -lt 300) -or $st -eq 304)) { $tr = 'pagina' }
        else { $tr = 'otro' }
        $esPag = ($tr -eq 'pagina')

        # visitante = IP + UA
        $clave = $ip + '|' + $ua
        $v = $null
        if (-not $visitantes.TryGetValue($clave, [ref]$v)) {
            $sigId++
            $cl = Clasificar-Ua $ua
            $v = [Visitante]::new()
            $v.Id = $sigId; $v.Ip = $ip; $v.Ua = $ua; $v.Bot = $cl[0]; $v.Tipo = $cl[1]
            $v.Primera = $fh; $v.Ultima = $fh
            $v.Urls = New-Object 'System.Collections.Generic.HashSet[string]'
            $v.CsvIni = (Csv (Seud $ip 'ip_')) + ';' + (Csv (Seud (Subred $ip) 'net_')) + ';' + $sigId
            $v.CsvFin = (Csv $ua) + ';' + $cl[1] + ';' + (Csv $cl[0])
            $visitantes[$clave] = $v
        }
        $esBot = ($v.Tipo -ne 'humano')
        $v.Peticiones++; $v.Bytes += $by
        if ([string]::CompareOrdinal($fh, $v.Primera) -lt 0) { $v.Primera = $fh }
        if ([string]::CompareOrdinal($fh, $v.Ultima) -gt 0) { $v.Ultima = $fh }
        if ($tr -eq 'recurso') { $v.Recursos++ }
        if ($esPag) {
            $v.Paginas++
            [void]$v.Urls.Add($ruta)
            if ($ref -ne '-' -and $ref -ne '') { $v.PaginasConReferer++ }
            $min = $fh.Substring(0, 16)
            if ($min -eq $v.MinActual) { $v.CuentaMin++ } else { $v.MinActual = $min; $v.CuentaMin = 1 }
            if ($v.CuentaMin -gt $v.MaxPagMin) { $v.MaxPagMin = $v.CuentaMin }
        }
        $e4 = ($st -ge 400 -and $st -lt 500); $e5 = ($st -ge 500)
        if ($e4) { $v.E4++; if ($st -eq 404) { $v.E404++ } } elseif ($e5) { $v.E5++ }
        if ($ruta -eq '/robots.txt') { $v.Robots++ }
        if ($rxSensible.IsMatch($ruta)) { $v.Sensibles++ }

        # agregados dia / hora (se cachea el ultimo porque el log suele venir ordenado)
        $kh = $fh.Substring(0, 13) + ':00'
        if ($fecha -ne $kDia) { $kDia = $fecha; $aDia = $null; if (-not $porDia.TryGetValue($fecha, [ref]$aDia)) { $aDia = [Agregado]::new(); $porDia[$fecha] = $aDia } }
        if ($kh -ne $kHora) { $kHora = $kh; $aHora = $null; if (-not $porHora.TryGetValue($kh, [ref]$aHora)) { $aHora = [Agregado]::new(); $porHora[$kh] = $aHora } }
        $aDia.Sumar($ip, $v.Id, $by, $esPag, $esBot, $e4, $e5)
        $aHora.Sumar($ip, $v.Id, $by, $esPag, $esBot, $e4, $e5)

        if ($null -ne $wD) {
            if ($filasParte -ge $MAX_FILAS_EXCEL) {
                $wD.Close(); $parte++; $filasParte = 0
                $wD = Nuevo-Escritor (Join-Path $Salida ("01_peticiones_parte{0}.csv" -f $parte)) $cabDet
            }
            $wD.WriteLine([Util]::Linea($fecha, $hora, $v.CsvIni, $metodo, $ruta, $query, $st, $by, $ref, $v.CsvFin, $tr))
            $filasParte++
        }
    }
    $lr.Close()
}
if ($null -ne $wD) { $wD.Close() }

# ------------------------------------------------------------ puntuacion
# Heuristica 0-100. >=60 alto, 30-59 medio. Ver LEEME.txt
$rxGoogleIp = New-Object regex('^(66\.249\.|64\.233\.|72\.14\.|74\.125\.|209\.85\.|216\.239\.|34\.|35\.|2001:4860:)', 'Compiled')
$rxAutomatticIp = New-Object regex('^(192\.0\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|198\.181\.11[6-9]\.|2a04:fa8)', 'Compiled')
$uasPorIp = @{}
foreach ($v in $visitantes.Values) { if ($uasPorIp.ContainsKey($v.Ip)) { $uasPorIp[$v.Ip]++ } else { $uasPorIp[$v.Ip] = 1 } }
# Subredes: detecta scraping distribuido (muchas IPs de la misma /24 que piden paginas sin cargar recursos)
$redStats = @{}
foreach ($v in $visitantes.Values) {
    $red = Subred $v.Ip
    if (-not $redStats.ContainsKey($red)) { $redStats[$red] = @{ Ips = (New-Object 'System.Collections.Generic.HashSet[string]'); Pag = 0; Rec = 0 } }
    $x = $redStats[$red]; [void]$x.Ips.Add($v.Ip); $x.Pag += $v.Paginas; $x.Rec += $v.Recursos
}
$redSospechosa = @{}
foreach ($k in $redStats.Keys) { $x = $redStats[$k]; if ($x.Ips.Count -ge 10 -and $x.Pag -ge 50 -and $x.Rec / $x.Pag -lt 0.1) { $redSospechosa[$k] = $x.Ips.Count } }
foreach ($v in $visitantes.Values) {
    $s = 0; $mot = New-Object 'System.Collections.Generic.List[string]'
    if ($v.Tipo -eq 'herramienta') { $s += 30; $mot.Add('UA de herramienta/script') }
    if ($v.Bot -eq 'Google' -and -not $rxGoogleIp.IsMatch($v.Ip)) { $s += 40; $mot.Add('Dice ser Googlebot desde IP no Google') }
    if ($v.Bot -eq 'WordPress/Jetpack' -and $v.Ua -match 'Jetpack|WordPress\.com' -and -not $rxAutomatticIp.IsMatch($v.Ip)) { $s += 40; $mot.Add('Dice ser Jetpack desde IP no Automattic') }
    $red = Subred $v.Ip
    if ($redSospechosa.ContainsKey($red) -and $v.Paginas -gt 0) { $s += 30; $mot.Add("Subred con $($redSospechosa[$red]) IPs pidiendo paginas sin recursos") }
    if ($uasPorIp[$v.Ip] -ge 5) { $s += 20; $mot.Add("La IP usa $($uasPorIp[$v.Ip]) user agents distintos") }
    if ($v.MaxPagMin -ge 30) { $s += 30; $mot.Add("$($v.MaxPagMin) paginas en 1 minuto") }
    elseif ($v.MaxPagMin -ge 10) { $s += 20; $mot.Add("$($v.MaxPagMin) paginas en 1 minuto") }
    if ($v.Paginas -ge 500) { $s += 25; $mot.Add("$($v.Paginas) paginas vistas") }
    elseif ($v.Paginas -ge 100) { $s += 15; $mot.Add("$($v.Paginas) paginas vistas") }
    if ($v.Tipo -eq 'humano' -and $v.Paginas -ge 10) {
        if ($v.Recursos -eq 0) { $s += 25; $mot.Add('No descarga CSS/JS/imagenes') }
        elseif ($v.Recursos / $v.Paginas -lt 0.5) { $s += 15; $mot.Add('Descarga muy pocos recursos') }
        if ($v.PaginasConReferer -eq 0) { $s += 10; $mot.Add('Nunca envia referer') }
    }
    if ($v.Tipo -eq 'humano' -and $v.Robots -gt 0) { $s += 15; $mot.Add('UA de navegador pidiendo robots.txt') }
    if ($v.E404 -ge 10 -and $v.E404 / $v.Peticiones -ge 0.3) { $s += 20; $mot.Add("$($v.E404) respuestas 404") }
    if ($v.Sensibles -ge 5) { $s += 25; $mot.Add("$($v.Sensibles) accesos a rutas sensibles") }
    elseif ($v.Sensibles -gt 0) { $s += 15; $mot.Add("$($v.Sensibles) accesos a rutas sensibles") }
    if ($wafPorIp.ContainsKey($v.Ip)) { $s += 20; $mot.Add("$($wafPorIp[$v.Ip]) bloqueos WAF de la IP") }
    if ($s -gt 100) { $s = 100 }
    $v.Score = $s
    $v.Motivos = $mot -join ' | '
    $v.Nivel = if ($s -ge 60) { 'alto' } elseif ($s -ge 30) { 'medio' } else { 'bajo' }
}
$idsSospechosos = New-Object 'System.Collections.Generic.HashSet[int]'
foreach ($v in $visitantes.Values) { if ($v.Score -ge 60) { [void]$idsSospechosos.Add($v.Id) } }

# ------------------------------------------------------------ salidas
function Escribir-Agregado($dic, [string]$ruta, [string]$colClave) {
    $w = Nuevo-Escritor $ruta "$colClave;peticiones;paginas_vistas;pv_humanas;pv_humanas_limpias;ips_unicas;ips_humanas;visitantes_humanos;visitantes_humanos_limpios;peticiones_bots;ips_bots;pct_trafico_bot;errores_4xx;errores_5xx;mb_servidos"
    foreach ($k in $dic.Keys) {
        $a = $dic[$k]
        $visL = 0; $pvL = 0
        foreach ($kv in $a.VisHumanos.GetEnumerator()) { if (-not $idsSospechosos.Contains($kv.Key)) { $visL++; $pvL += $kv.Value } }
        $pctBot = if ($a.Peticiones -gt 0) { 100.0 * $a.PetBots / $a.Peticiones } else { 0 }
        $w.WriteLine(($k, $a.Peticiones, $a.Paginas, $a.PvHumanas, $pvL, $a.Ips.Count, $a.IpsHumanas.Count, $a.VisHumanos.Count, $visL, $a.PetBots, $a.IpsBots.Count, (Dec $pctBot), $a.E4, $a.E5, (Dec ($a.Bytes / 1MB))) -join ';')
    }
    $w.Close()
}
if ($total -gt 0) {
    Escribir-Agregado $porDia (Join-Path $Salida '02_resumen_diario.csv') 'fecha'
    Escribir-Agregado $porHora (Join-Path $Salida '03_resumen_horario.csv') 'fecha_hora'

    # visitantes
    $w = Nuevo-Escritor (Join-Path $Salida '04_visitantes.csv') 'visitante_id;ip;subred;user_agent;tipo_trafico;bot;nivel_sospecha;puntuacion;motivos;primera;ultima;duracion_min;peticiones;paginas;urls_distintas;recursos;max_paginas_minuto;paginas_por_minuto;robots_txt;rutas_sensibles;bloqueos_waf;errores_4xx;errores_404;errores_5xx;pct_paginas_con_referer;mb'
    foreach ($v in ($visitantes.Values | Sort-Object -Property @{Expression = 'Score'; Descending = $true }, @{Expression = 'Peticiones'; Descending = $true })) {
        $t1 = [datetime]::ParseExact($v.Primera, 'yyyy-MM-dd HH:mm:ss', $null)
        $t2 = [datetime]::ParseExact($v.Ultima, 'yyyy-MM-dd HH:mm:ss', $null)
        $dur = ($t2 - $t1).TotalMinutes
        $ppm = if ($dur -ge 1) { $v.Paginas / $dur } else { $v.Paginas }
        $pr = if ($v.Paginas -gt 0) { 100.0 * $v.PaginasConReferer / $v.Paginas } else { 0 }
        $waf = if ($wafPorIp.ContainsKey($v.Ip)) { $wafPorIp[$v.Ip] } else { 0 }
        $w.WriteLine(($v.Id, (Csv (Seud $v.Ip 'ip_')), (Csv (Seud (Subred $v.Ip) 'net_')), (Csv $v.Ua), $v.Tipo, (Csv $v.Bot), $v.Nivel, $v.Score, (Csv $v.Motivos), $v.Primera, $v.Ultima, (Dec $dur), $v.Peticiones, $v.Paginas, $v.Urls.Count, $v.Recursos, $v.MaxPagMin, (Dec $ppm), $v.Robots, $v.Sensibles, $waf, $v.E4, $v.E404, $v.E5, (Dec $pr), (Dec ($v.Bytes / 1MB))) -join ';')
    }
    $w.Close()

    # IPs y subredes (detecta rotacion de UA o de IPs)
    $ips = @{}; $redes = @{}
    foreach ($v in $visitantes.Values) {
        if (-not $ips.ContainsKey($v.Ip)) { $ips[$v.Ip] = [pscustomobject]@{ Ip = $v.Ip; Pet = 0; Pag = 0; Uas = 0; Max = 0; Tipos = (New-Object 'System.Collections.Generic.HashSet[string]'); Primera = $v.Primera; Ultima = $v.Ultima } }
        $o = $ips[$v.Ip]; $o.Pet += $v.Peticiones; $o.Pag += $v.Paginas; $o.Uas++; [void]$o.Tipos.Add($v.Tipo)
        if ($v.Score -gt $o.Max) { $o.Max = $v.Score }
        if ([string]::CompareOrdinal($v.Primera, $o.Primera) -lt 0) { $o.Primera = $v.Primera }
        if ([string]::CompareOrdinal($v.Ultima, $o.Ultima) -gt 0) { $o.Ultima = $v.Ultima }
    }
    $w = Nuevo-Escritor (Join-Path $Salida '05_ips.csv') 'ip;subred;peticiones;paginas;user_agents_distintos;tipos_trafico;puntuacion_max;bloqueos_waf;primera;ultima'
    foreach ($o in ($ips.Values | Sort-Object -Property @{Expression = 'Max'; Descending = $true }, @{Expression = 'Pet'; Descending = $true })) {
        $red = Subred $o.Ip
        if (-not $redes.ContainsKey($red)) { $redes[$red] = [pscustomobject]@{ Red = $red; Ips = 0; Pet = 0; Pag = 0; Max = 0; Waf = 0 } }
        $rr = $redes[$red]; $rr.Ips++; $rr.Pet += $o.Pet; $rr.Pag += $o.Pag; if ($o.Max -gt $rr.Max) { $rr.Max = $o.Max }
        $waf = if ($wafPorIp.ContainsKey($o.Ip)) { $wafPorIp[$o.Ip] } else { 0 }
        $rr.Waf += $waf
        $w.WriteLine(((Csv (Seud $o.Ip 'ip_')), (Csv (Seud $red 'net_')), $o.Pet, $o.Pag, $o.Uas, (Csv (($o.Tipos | Sort-Object) -join ',')), $o.Max, $waf, $o.Primera, $o.Ultima) -join ';')
    }
    $w.Close()
    $w = Nuevo-Escritor (Join-Path $Salida '06_subredes.csv') 'subred;ips_distintas;peticiones;paginas;puntuacion_max;bloqueos_waf'
    foreach ($rr in ($redes.Values | Sort-Object -Property @{Expression = 'Pet'; Descending = $true })) {
        $w.WriteLine(((Csv (Seud $rr.Red 'net_')), $rr.Ips, $rr.Pet, $rr.Pag, $rr.Max, $rr.Waf) -join ';')
    }
    $w.Close()

    # user agents
    $uas = @{}
    foreach ($v in $visitantes.Values) {
        if (-not $uas.ContainsKey($v.Ua)) { $uas[$v.Ua] = [pscustomobject]@{ Ua = $v.Ua; Tipo = $v.Tipo; Bot = $v.Bot; Pet = 0; Pag = 0; Ips = 0 } }
        $u = $uas[$v.Ua]; $u.Pet += $v.Peticiones; $u.Pag += $v.Paginas; $u.Ips++
    }
    $w = Nuevo-Escritor (Join-Path $Salida '07_user_agents.csv') 'user_agent;tipo_trafico;bot;peticiones;paginas;ips_distintas'
    foreach ($u in ($uas.Values | Sort-Object -Property @{Expression = 'Pet'; Descending = $true })) {
        $w.WriteLine(((Csv $u.Ua), $u.Tipo, (Csv $u.Bot), $u.Pet, $u.Pag, $u.Ips) -join ';')
    }
    $w.Close()
}

# ------------------------------------------------------------ resumen
$hum = @($visitantes.Values | Where-Object { $_.Tipo -eq 'humano' -and $_.Paginas -gt 0 })
$humL = @($hum | Where-Object { $_.Score -lt 60 })
$alto = @($visitantes.Values | Where-Object { $_.Score -ge 60 })
$medio = @($visitantes.Values | Where-Object { $_.Score -ge 30 -and $_.Score -lt 60 })
$rango = if ($porDia.Count -gt 0) { "$(@($porDia.Keys)[0]) a $(@($porDia.Keys)[-1])" } else { '-' }
$res = @"
ANALISIS DE LOGS  $(Get-Date -Format 'yyyy-MM-dd HH:mm')
Ficheros acceso: $(($logsAcceso | ForEach-Object Name) -join ', ')
Ficheros error:  $(($logsError | ForEach-Object Name) -join ', ')
Periodo:         $rango
Lineas acceso:   $total  (no reconocidas: $malformadas)
Lineas error:    $lineasErr
Seudonimizado:   $(if ($Seudonimizar) { 'si' } else { 'no' })

CARDINALIDAD (para comparar con GA4)
  IPs unicas totales:                         $(@($visitantes.Values | ForEach-Object Ip | Sort-Object -Unique).Count)
  Visitantes humanos (IP+UA con >=1 pagina):  $($hum.Count)
  Visitantes humanos limpios (sin sospecha alta): $($humL.Count)
  Paginas vistas humanas limpias:             $([int](($humL | Measure-Object -Property Paginas -Sum).Sum))
  Nota: suma de visitantes diarios != visitantes del periodo. Usa 02_resumen_diario para comparar dia a dia.

SOSPECHA DE SCRAPING / ABUSO
  Visitantes nivel alto (>=60):  $($alto.Count)
  Visitantes nivel medio (30-59): $($medio.Count)
  IPs con bloqueos WAF:           $($wafPorIp.Count)

TOP 10 POR PUNTUACION
"@
foreach ($v in ($visitantes.Values | Sort-Object -Property @{Expression = 'Score'; Descending = $true }, @{Expression = 'Peticiones'; Descending = $true } | Select-Object -First 10)) {
    $uaC = if ($v.Ua.Length -gt 60) { $v.Ua.Substring(0, 60) + '...' } else { $v.Ua }
    $res += "`r`n  [$($v.Score)] $(Seud $v.Ip 'ip_')  $($v.Peticiones) pet.  $uaC`r`n        $($v.Motivos)"
}
$res += "`r`n`r`nTiempo: $([Math]::Round($reloj.Elapsed.TotalSeconds, 1)) s`r`n"
[System.IO.File]::WriteAllText((Join-Path $Salida '00_resumen.txt'), $res, $utf8Bom)
Write-Host ''
Write-Host $res
Write-Host "Resultados en: $Salida" -ForegroundColor Green
