#!/bin/bash
# ============================================================
# lib_common.sh — singbox-lite 共享函数库
# 由 singbox.sh / advanced_relay.sh / xray_manager.sh 统一 source，
# 消除三份脚本各自维护的重复实现（颜色、编解码、IP、白名单校验、
# 原子 JSON/YAML 修改、端口检测、iptables 持久化、内存探测等）。
# 本文件只定义函数与默认变量，source 时无任何副作用。
# ============================================================

_LIB_COMMON_SOURCED=1

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'
ORANGE='\033[0;33m'

# --- 打印消息函数 (统一输出到 stderr，避免干扰变量捕获) ---
_info() { echo -e "${CYAN}[信息] $1${NC}" >&2; }
_success() { echo -e "${GREEN}[成功] $1${NC}" >&2; }
_warn() { echo -e "${YELLOW}[注意] $1${NC}" >&2; }
_warning() { _warn "$1"; } # 别名兼容
_error() { echo -e "${RED}[错误] $1${NC}" >&2; }

# --- 默认伪装 SNI 与随机选择 ---
DEFAULT_SNI="www.amd.com"
SNI_CANDIDATES=(
    "www.apple.com"
    "www.microsoft.com"
    "www.amazon.com"
    "www.bing.com"
    "www.samsung.com"
    "www.adobe.com"
    "www.mozilla.org"
    "www.amd.com"
    "www.nvidia.com"
)

_random_sni() {
    local count=${#SNI_CANDIDATES[@]}
    [ "$count" -gt 0 ] || { printf '%s' "$DEFAULT_SNI"; return; }
    printf '%s' "${SNI_CANDIDATES[$((RANDOM % count))]}"
}

_is_random_sni_input() {
    local input="${1//[[:space:]]/}"
    [[ "${input,,}" =~ ^(r|random|随机)$ ]]
}

_resolve_sni_input() {
    local input="${1//[[:space:]]/}"
    local fallback="${2:-$DEFAULT_SNI}"
    case "${input,,}" in
        r|random|随机) _random_sni ;;
        "") printf '%s' "$fallback" ;;
        *) printf '%s' "$input" ;;
    esac
}

# --- 编解码器 ---
_url_decode() {
    local data="${1//+/ }"
    # 先保护字面反斜杠，避免 printf %b 将其误当转义符处理
    data="${data//\\/\\\\}"
    printf '%b' "${data//%/\\x}"
}
_url_encode() {
    # 使用 jq 内建 @uri 过滤器，按字节执行标准 percent-encoding (UTF-8 安全)
    printf '%s' "$1" | jq -sRr @uri
}
_ss_base64_encode() {
    # Shadowsocks SIP002 规范要求 Base64 编码不带填充 (No Padding)
    printf '%s' "$1" | base64 | tr -d '\n\r ' | sed 's/=//g'
}

# --- 公网 IP 获取 (带进程内缓存) ---
server_ip=""
_get_public_ip() {
    [ -n "$server_ip" ] && [ "$server_ip" != "null" ] && { echo "$server_ip"; return; }
    local ip=$(timeout 5 curl -s4 --max-time 2 icanhazip.com 2>/dev/null || timeout 5 curl -s4 --max-time 2 ipinfo.io/ip 2>/dev/null)
    [ -z "$ip" ] && ip=$(timeout 5 curl -s6 --max-time 2 icanhazip.com 2>/dev/null || timeout 5 curl -s6 --max-time 2 ipinfo.io/ip 2>/dev/null)
    server_ip="$ip"
    echo "$ip"
}
_get_ip() { _get_public_ip; } # 别名兼容

# ---------------- 入站来源 IP 白名单 (通用校验) ----------------
# 将单个 IP 统一转换为 CIDR；sing-box 与 Xray 共用同一套输入格式。
_validate_inbound_ipv6_part() {
    local part="$1"
    [ -z "$part" ] && return 0
    [[ "$part" != :* && "$part" != *: ]] || return 1

    local hextets=()
    IFS=':' read -r -a hextets <<< "$part"
    [ "${#hextets[@]}" -gt 0 ] || return 1
    local hextet
    for hextet in "${hextets[@]}"; do
        [[ "$hextet" =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    done
    return 0
}

_normalize_inbound_ip() {
    local value="$1"
    local address="" prefix=""
    value="${value#[}"
    value="${value%]}"

    if [[ "$value" == */* ]]; then
        address="${value%%/*}"
        prefix="${value#*/}"
        [[ "$prefix" != */* ]] || return 1
    else
        address="$value"
    fi

    if [[ "$address" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
        local octets=()
        IFS='.' read -r -a octets <<< "$address"
        [ "${#octets[@]}" -eq 4 ] || return 1
        local octet
        for octet in "${octets[@]}"; do
            [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
            [ "$((10#$octet))" -le 255 ] || return 1
        done
        [ -z "$prefix" ] && prefix=32
        [[ "$prefix" =~ ^[0-9]+$ ]] || return 1
        [ "$((10#$prefix))" -le 32 ] || return 1
        printf '%d.%d.%d.%d/%d' "$((10#${octets[0]}))" "$((10#${octets[1]}))" "$((10#${octets[2]}))" "$((10#${octets[3]}))" "$((10#$prefix))"
        return 0
    fi

    [[ "$address" == *:* ]] || return 1
    [[ "$address" =~ ^[0-9A-Fa-f:]+$ ]] || return 1
    [ -z "$prefix" ] && prefix=128
    [[ "$prefix" =~ ^[0-9]+$ ]] || return 1
    [ "$((10#$prefix))" -le 128 ] || return 1

    local left="" right="" left_count=0 right_count=0 total=0
    if [[ "$address" == *::* ]]; then
        # IPv6 只能有一个压缩段，且压缩段至少代表一个 hextet。
        [[ "${address#*::}" != *::* ]] || return 1
        left="${address%%::*}"
        right="${address#*::}"
        _validate_inbound_ipv6_part "$left" || return 1
        _validate_inbound_ipv6_part "$right" || return 1
        [ -n "$left" ] && left_count=$(awk -F: '{print NF}' <<< "$left")
        [ -n "$right" ] && right_count=$(awk -F: '{print NF}' <<< "$right")
        total=$((left_count + right_count))
        [ "$total" -le 7 ] || return 1
    else
        _validate_inbound_ipv6_part "$address" || return 1
        total=$(awk -F: '{print NF}' <<< "$address")
        [ "$total" -eq 8 ] || return 1
    fi
    printf '%s/%d' "$address" "$((10#$prefix))"
}

_normalize_inbound_ip_list() {
    local raw="${1//,/ }"
    local compact="${raw//[[:space:]]/}"
    [ -n "$compact" ] || return 0

    local values=()
    read -r -a values <<< "$raw"
    [ "${#values[@]}" -gt 0 ] || return 1

    local value normalized result=()
    for value in "${values[@]}"; do
        normalized=$(_normalize_inbound_ip "$value") || return 1
        result+=("$normalized")
    done
    local IFS=' '
    printf '%s' "${result[*]}"
}

# 交互式询问入站来源白名单，结果写入全局变量 ALLOWED_INBOUND_IPS
_prompt_allowed_inbound_ips() {
    ALLOWED_INBOUND_IPS=""
    local raw="" normalized=""
    while true; do
        read -p "允许的入站来源 IP/CIDR（多个用逗号或空格分隔，留空不限）: " raw
        normalized=$(_normalize_inbound_ip_list "$raw")
        if [ $? -eq 0 ]; then
            ALLOWED_INBOUND_IPS="$normalized"
            [ -n "$normalized" ] && _info "已启用入站来源 IP 白名单: ${normalized// /, }"
            return 0
        fi
        _error "IP/CIDR 格式无效，请重新输入。例如: 203.0.113.10, 2001:db8::/32"
    done
}

# --- 系统环境检测 ---
_detect_init_system() {
    if [ -f /sbin/openrc-run ] || command -v rc-service &>/dev/null; then
        export INIT_SYSTEM="openrc"
        export SERVICE_FILE="/etc/init.d/sing-box"
    elif command -v systemctl &>/dev/null; then
        export INIT_SYSTEM="systemd"
        export SERVICE_FILE="/etc/systemd/system/sing-box.service"
    else
        export INIT_SYSTEM="unknown"
        export SERVICE_FILE=""
    fi
}

# --- 端口占用检查 (ss → netstat → /proc/net 三级回退) ---
_check_port_occupied() {
    local port=$1
    local proto=${2:-tcp}
    local hex_port
    if [[ "$proto" == "tcp" ]]; then
        if command -v ss &>/dev/null; then
            ss -lnpt | grep -q ":${port} " && return 0
        elif command -v netstat &>/dev/null; then
            netstat -lnpt | grep -q ":${port} " && return 0
        fi
    else
        if command -v ss &>/dev/null; then
            ss -lnpu | grep -q ":${port} " && return 0
        elif command -v netstat &>/dev/null; then
            netstat -lnpu | grep -q ":${port} " && return 0
        fi
    fi

    # 精简 Alpine/Podman 可能没有 ss/netstat，直接读取 /proc/net 保证端口检测仍可工作
    hex_port=$(printf '%04X' "$port" 2>/dev/null)
    [ -z "$hex_port" ] && return 1
    if [[ "$proto" == "tcp" ]]; then
        awk -v p="$hex_port" '$2 ~ ":" p "$" {found=1} END{exit !found}' /proc/net/tcp /proc/net/tcp6 2>/dev/null && return 0
    else
        awk -v p="$hex_port" '$2 ~ ":" p "$" {found=1} END{exit !found}' /proc/net/udp /proc/net/udp6 2>/dev/null && return 0
    fi
    return 1
}

# --- IPTables 规则持久化 (跨 Debian/Alpine 双发行版兼容) ---
_save_iptables_rules() {
    if command -v netfilter-persistent &>/dev/null; then
        # Debian/Ubuntu: 使用 netfilter-persistent 统一持久化 (含 v4+v6)
        netfilter-persistent save >/dev/null 2>&1
    else
        # Alpine / 通用方案: 分别保存 v4 和 v6 规则到标准路径
        if command -v iptables-save &>/dev/null; then
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null
        fi
        if command -v ip6tables-save &>/dev/null; then
            mkdir -p /etc/iptables
            ip6tables-save > /etc/iptables/rules.v6 2>/dev/null
        fi
    fi
    # Alpine OpenRC: 尝试使用 rc-service 保存
    if command -v rc-service &>/dev/null; then
        rc-service iptables save 2>/dev/null
        rc-service ip6tables save 2>/dev/null
    fi
}

# --- 智能包管理 ---
_pkg_install() {
    local pkgs="$*"
    [ -z "$pkgs" ] && return 0
    if command -v apk &>/dev/null; then
        apk add --no-cache $pkgs >/dev/null 2>&1
    elif command -v apt-get &>/dev/null; then
        # 全新 LXC/容器上 apt 缓存可能为空，必须先 update
        if [ ! -d "/var/lib/apt/lists" ] || [ "$(ls -A /var/lib/apt/lists/ 2>/dev/null | wc -l)" -le 1 ]; then
            apt-get update -qq >/dev/null 2>&1
        fi
        DEBIAN_FRONTEND=noninteractive apt-get install -y $pkgs >/dev/null 2>&1 || {
            # 兜底：如果安装失败，强制刷新索引后重试
            apt-get update -qq >/dev/null 2>&1
            DEBIAN_FRONTEND=noninteractive apt-get install -y $pkgs >/dev/null 2>&1
        }
    elif command -v yum &>/dev/null; then yum install -y $pkgs >/dev/null 2>&1
    elif command -v dnf &>/dev/null; then dnf install -y $pkgs >/dev/null 2>&1
    fi
}

# --- 原子修改 JSON 文件 ---
_atomic_modify_json() {
    local file="$1" filter="$2"
    [ ! -f "$file" ] && return 1
    local tmp="${file}.tmp"
    if jq "$filter" "$file" > "$tmp"; then mv "$tmp" "$file"
    else _error "修改JSON失败: $file"; rm -f "$tmp"; return 1; fi
}

# --- 工具与内存环境 ---
YQ_BINARY="${YQ_BINARY:-/usr/local/bin/yq}"

# 安装 yq
_install_yq() {
    if ! command -v yq &>/dev/null; then
        _info "安装 yq..."
        local arch=$(uname -m)
        case $arch in x86_64|amd64) arch='amd64' ;; aarch64|arm64) arch='arm64' ;; *) arch='amd64' ;; esac
        mkdir -p "$(dirname "$YQ_BINARY")" || return 1
        if ! wget -qO "$YQ_BINARY" "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_$arch"; then
            rm -f "$YQ_BINARY"
            _error "yq 下载失败。"
            return 1
        fi
        chmod +x "$YQ_BINARY" || return 1
        _release_install_cache
    fi
}

# 原子修改 YAML 文件
_atomic_modify_yaml() {
    local file="$1" filter="$2"
    [ ! -f "$file" ] && return 1
    _install_yq || return 1
    cp "$file" "${file}.tmp"
    if ${YQ_BINARY} eval "$filter" -i "$file"; then
        rm "${file}.tmp"
        # clash.yaml 发生变更时使查找缓存失效
        [ "$file" == "${CLASH_YAML_FILE:-}" ] && _yaml_cache_reset
    else
        _error "修改YAML失败: $file"; mv "${file}.tmp" "$file"; return 1
    fi
}

# --- Clash YAML 查找缓存 ---
# 查看节点列表等场景原先每个节点触发 2-3 次 yq 进程；
# 这里改为一次性全量载入内存哈希，供 _find_proxy_name / _get_proxy_field 查询。
declare -A _YAML_NAME_BY_PORT _YAML_SERVER _YAML_SERVERNAME _YAML_SNI _YAML_SKIP _YAML_JSON
_YAML_443_NAMES=()
_YAML_CACHE_LOADED=false

_yaml_cache_reset() {
    _YAML_NAME_BY_PORT=(); _YAML_SERVER=(); _YAML_SERVERNAME=()
    _YAML_SNI=(); _YAML_SKIP=(); _YAML_JSON=()
    _YAML_443_NAMES=()
    _YAML_CACHE_LOADED=false
}

_yaml_cache_init() {
    [ "$_YAML_CACHE_LOADED" = true ] && return 0
    _YAML_CACHE_LOADED=true
    [ -n "${CLASH_YAML_FILE:-}" ] || return 0
    _install_yq || return 0

    local yport yname yserver yservername ysni yskip
    while IFS=$'\t' read -r yport yname yserver yservername ysni yskip; do
        [ -n "$yname" ] || continue
        _YAML_NAME_BY_PORT["$yport"]="${_YAML_NAME_BY_PORT[$yport]:-$yname}"
        _YAML_SERVER["$yname"]="$yserver"
        _YAML_SERVERNAME["$yname"]="$yservername"
        _YAML_SNI["$yname"]="$ysni"
        _YAML_SKIP["$yname"]="$yskip"
        [ "$yport" == "443" ] && _YAML_443_NAMES+=("$yname")
    done < <(${YQ_BINARY} eval '.proxies[] | [(.port|tostring), (.name // ""), (.server // ""), (.servername // ""), (.sni // ""), ((."skip-cert-verify" // "")|tostring)] | @tsv' "$CLASH_YAML_FILE" 2>/dev/null)

    # 预载每个节点的紧凑 JSON 行 (用于 mihomo 单行展示)
    local jname jline
    while IFS=$'\t' read -r jname jline; do
        [ -n "$jname" ] && _YAML_JSON["$jname"]="$jline"
    done < <(${YQ_BINARY} eval -o=json -I=0 '.proxies[]' "$CLASH_YAML_FILE" 2>/dev/null | \
        jq -rs 'map({key: (.name // ""), value: tojson}) | from_entries | to_entries[] | [.key, .value] | @tsv' 2>/dev/null)
    return 0
}

# 按端口查找代理名称 (行为与旧版一致：先精确匹配端口，失败后按 443 + 类型回退)
_find_proxy_name() {
    local port="$1" type="$2"
    _yaml_cache_init
    local name="${_YAML_NAME_BY_PORT[$port]:-}"
    if [ -z "$name" ]; then
        local cand pat="*${type,,}*"
        [ -z "${type// /}" ] && pat="*"
        for cand in "${_YAML_443_NAMES[@]}"; do
            [[ "${cand,,}" == ${pat} ]] && { name="$cand"; break; }
        done
    fi
    printf '%s' "$name"
}

# 读取代理字段；常用字段走内存缓存，其余字段回退单次 yq
_get_proxy_field() {
    local proxy_name="$1" field="$2"
    _yaml_cache_init
    case "$field" in
        .server)           printf '%s\n' "${_YAML_SERVER[$proxy_name]:-}" ;;
        .servername)       printf '%s\n' "${_YAML_SERVERNAME[$proxy_name]:-}" ;;
        .sni)              printf '%s\n' "${_YAML_SNI[$proxy_name]:-}" ;;
        .skip-cert-verify) printf '%s\n' "${_YAML_SKIP[$proxy_name]:-}" ;;
        *)
            _install_yq || return 1
            export PROXY_NAME="$proxy_name"
            ${YQ_BINARY} eval '.proxies[] | select(.name == env(PROXY_NAME)) | '"$field" "${CLASH_YAML_FILE}" 2>/dev/null | head -n 1
            ;;
    esac
}

# 获取代理的紧凑 JSON 单行 (mihomo 展示用)
_get_proxy_json_line() {
    local proxy_name="$1"
    _yaml_cache_init
    printf '%s' "${_YAML_JSON[$proxy_name]:-}"
}

# 打印 mihomo / Clash.Meta 单行节点配置 (YAML 兼容的 JSON flow style)
_show_mihomo_proxy_line() {
    local proxy_json="$1"
    [ -z "$proxy_json" ] && return
    local compact=$(echo "$proxy_json" | jq -c .)
    [ -z "$compact" ] && return
    echo ""
    echo -e "${YELLOW}═══════════════ mihomo / Clash.Meta 节点 ═══════════════${NC}"
    echo -e "${CYAN}- ${compact}${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════════${NC}"
}

# --- Clash YAML 节点增删 (统一入口，保证三个脚本行为一致) ---
_add_node_to_yaml() {
    local proxy_json="$1"
    _install_yq || return 1
    local proxy_name=$(echo "$proxy_json" | jq -r .name)
    _atomic_modify_yaml "$CLASH_YAML_FILE" ".proxies |= . + [${proxy_json}] | .proxies |= unique_by(.name)"
    export PROXY_NAME="$proxy_name"
    ${YQ_BINARY} eval '.proxy-groups[] |= (select(.name == "节点选择") | .proxies |= . + [env(PROXY_NAME)] | .proxies |= unique)' -i "$CLASH_YAML_FILE"
    _show_mihomo_proxy_line "$proxy_json"
}
_remove_node_from_yaml() {
    local proxy_name="$1"
    _install_yq || return 1
    export PROXY_NAME="$proxy_name"
    ${YQ_BINARY} eval 'del(.proxies[] | select(.name == env(PROXY_NAME)))' -i "$CLASH_YAML_FILE"
    ${YQ_BINARY} eval '.proxy-groups[] |= (select(.name == "节点选择") | .proxies |= del(.[] | select(. == env(PROXY_NAME))))' -i "$CLASH_YAML_FILE"
    _yaml_cache_reset
}

# --- 内存环境探测 ---
# 获取真实可用内存上限，优先读取 cgroup 限额以适配 Docker/Podman 低内存容器
_get_total_mem_mb() {
    local total_mem_mb=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')
    local cgroup_limit=""

    [ -z "$total_mem_mb" ] && total_mem_mb=128

    if [ -r /sys/fs/cgroup/memory.max ]; then
        cgroup_limit=$(cat /sys/fs/cgroup/memory.max 2>/dev/null)
        if [ "$cgroup_limit" != "max" ] && [ -n "$cgroup_limit" ]; then
            total_mem_mb=$((cgroup_limit / 1024 / 1024))
        fi
    elif [ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        cgroup_limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null)
        if [ -n "$cgroup_limit" ] && [ "$cgroup_limit" -lt 9223372036854771712 ] 2>/dev/null; then
            total_mem_mb=$((cgroup_limit / 1024 / 1024))
        fi
    fi

    [ "$total_mem_mb" -lt 16 ] && total_mem_mb=16
    echo "$total_mem_mb"
}

# 判断是否为低内存环境；64M Podman/Alpine 会走更保守的依赖和运行时策略
_is_low_mem_env() {
    local total_mem_mb=$(_get_total_mem_mb)
    [ "$total_mem_mb" -le 96 ]
}

# 安装阶段会产生较多文件缓存，低内存容器中尽力释放；失败不影响主流程
_release_install_cache() {
    sync 2>/dev/null || true
    if [ -w /proc/sys/vm/drop_caches ]; then
        if { echo 1 > /proc/sys/vm/drop_caches; } 2>/dev/null; then
            _info "已尝试释放安装产生的文件缓存。"
        fi
    fi
    return 0
}
