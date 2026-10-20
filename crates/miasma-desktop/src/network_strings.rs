//! Text of the Network section in Settings and of the reachability check, in the three
//! languages the app ships. Fixed labels are fields of [`NetStrings`]; texts that depend on a
//! value of the reachability report (a path, a result, a suggestion) are looked up by the
//! functions below. The completeness tests at the bottom fail when a language lacks a text.

use miasma_core::transport::reach::{AdviceCode, Group, Outcome, Role};

use crate::locale::Locale;

macro_rules! net_strings {
    ($($f:ident),* $(,)?) => {
        /// Fixed labels and explanations of the Network section.
        pub struct NetStrings { $(pub $f: &'static str),* }
        impl NetStrings {
            /// Every field with its name, for the completeness test.
            #[cfg(test)]
            fn all(&self) -> Vec<(&'static str, &'static str)> {
                vec![$((stringify!($f), self.$f)),*]
            }
        }
    };
}

net_strings! {
    heading, intro, load_failed,
    mode_label, mode_public, mode_own, mode_direct,
    mode_desc_public, mode_desc_own, mode_desc_direct,
    relays_label, relays_desc, relay_none, relay_placeholder, relay_add, relay_remove,
    err_url_empty, err_url_not_https, err_url_space, err_url_userinfo, err_url_host,
    err_url_port, err_url_query, err_url_dup, err_url_toomany,
    issue_own_needs_url, issue_retry_range,
    lan_label, lan_on, lan_off, lan_desc,
    ca_label, ca_choose, ca_clear, ca_none, ca_desc,
    ca_ok, ca_missing, ca_unreadable, ca_too_large, ca_invalid,
    retry_label, retry_desc, retry_unit,
    restart_tag, saved_notice, save_failed, unsaved, save, discard,
    check_heading, check_desc, check_button, check_running, check_cancel, check_cancelled,
    check_failed,
    col_path, col_target, col_result, col_reason,
    result_works, result_failed, result_skipped,
    summary, measured_rtt, measured_speed, no_rows,
    suggest_heading, suggest_none,
    save_report, report_saved, report_failed, report_file_name,
}

pub fn net_strings(locale: Locale) -> &'static NetStrings {
    match locale {
        Locale::En => &NET_EN,
        Locale::Ja => &NET_JA,
        Locale::ZhCn => &NET_ZH_CN,
    }
}

/// Pick one of three texts by language.
fn pick(locale: Locale, en: &'static str, ja: &'static str, zh: &'static str) -> &'static str {
    match locale {
        Locale::En => en,
        Locale::Ja => ja,
        Locale::ZhCn => zh,
    }
}

static NET_EN: NetStrings = NetStrings {
    heading: "Network",
    intro: "How Miasma connects to other computers. Changes are saved on this computer and take effect after Miasma's background service starts again.",
    load_failed: "The settings file could not be read. The default values are shown.",
    mode_label: "Connection:",
    mode_public: "Public relay",
    mode_own: "My own relay",
    mode_direct: "Direct only",
    mode_desc_public: "Uses the public relay and discovery servers of the iroh project. This is the default and needs no setup. While Miasma runs, this computer's address is published to the discovery service.",
    mode_desc_own: "Uses only the relay servers you list below instead of the public ones. Choose this when the public relay cannot be reached from your network.",
    mode_desc_direct: "Turns the relay-based path off. Receiving by share ID alone needs that path, so it will not work in this mode.",
    relays_label: "Relay addresses:",
    relays_desc: "Relay servers you run yourself. Only https:// addresses are accepted. They are used when \"My own relay\" is selected.",
    relay_none: "No relay address added yet.",
    relay_placeholder: "https://relay.example.org",
    relay_add: "Add",
    relay_remove: "Remove",
    err_url_empty: "Enter an address first.",
    err_url_not_https: "The address must start with https://.",
    err_url_space: "The address must not contain spaces.",
    err_url_userinfo: "The address must not contain a user name or password.",
    err_url_host: "The server name in the address is not valid.",
    err_url_port: "The port in the address is not valid (1 to 65535).",
    err_url_query: "The address must not contain ? or #.",
    err_url_dup: "This address is already in the list.",
    err_url_toomany: "The list is full (8 addresses at most).",
    issue_own_needs_url: "Add at least one relay address, or choose another connection.",
    issue_retry_range: "Enter a whole number of hours from 0 to 8760.",
    lan_label: "Same-network discovery:",
    lan_on: "On",
    lan_off: "Off",
    lan_desc: "Lets Miasma find other computers on the same local network. Turn it off on a network you do not trust.",
    ca_label: "Extra certificate:",
    ca_choose: "Choose file...",
    ca_clear: "Clear",
    ca_none: "No file chosen.",
    ca_desc: "A certificate file (PEM or DER) for a network that replaces the certificates of secure connections. Miasma trusts it in addition to the system certificates. Choose only a file you trust.",
    ca_ok: "{name}: {n} certificate(s) found.",
    ca_missing: "{name}: the file does not exist.",
    ca_unreadable: "{name}: the file cannot be read.",
    ca_too_large: "{name}: the file is too large for a certificate file.",
    ca_invalid: "{name}: this is not a valid certificate file.",
    retry_label: "Retry window:",
    retry_desc: "How long a send keeps retrying by itself when the other computer cannot be reached. 0 means it never gives up.",
    retry_unit: "hours",
    restart_tag: "Applies after restart",
    saved_notice: "Saved. Close Miasma completely and start it again for the change to take effect.",
    save_failed: "Could not save: {err}",
    unsaved: "There are changes that are not saved yet.",
    save: "Save",
    discard: "Discard changes",
    check_heading: "Check my network",
    check_desc: "Tries each way Miasma can connect from this network and shows which ones work. No personal data is sent. It takes up to 40 seconds and tests the saved settings above.",
    check_button: "Check my network",
    check_running: "Checking... {s} s",
    check_cancel: "Cancel",
    check_cancelled: "The check was cancelled.",
    check_failed: "The check could not run: {err}",
    col_path: "Path",
    col_target: "Target",
    col_result: "Result",
    col_reason: "Reason",
    result_works: "Works",
    result_failed: "Failed",
    result_skipped: "Skipped",
    summary: "{ok} work, {bad} failed, {skip} skipped. The check took {s} s.",
    measured_rtt: "round trip {ms} ms",
    measured_speed: "{kib} KiB/s",
    no_rows: "The check returned no results.",
    suggest_heading: "Suggested setup",
    suggest_none: "There is no suggestion for this result.",
    save_report: "Save report",
    report_saved: "Report saved to {path}.",
    report_failed: "Could not save the report: {err}",
    report_file_name: "network-report.json",
};

static NET_JA: NetStrings = NetStrings {
    heading: "ネットワーク",
    intro: "Miasma が他のコンピューターとつながる方法です。変更はこのコンピューターに保存され、Miasma のバックグラウンドサービスを起動し直したあとに反映されます。",
    load_failed: "設定ファイルを読み込めませんでした。初期値を表示しています。",
    mode_label: "接続方法:",
    mode_public: "公開の中継サーバー",
    mode_own: "自分の中継サーバー",
    mode_direct: "直接のみ",
    mode_desc_public: "iroh プロジェクトが運営する公開の中継サーバーと探索サービスを使います。初期設定で、準備は要りません。Miasma の実行中、このコンピューターのアドレスが探索サービスに公開されます。",
    mode_desc_own: "公開の中継サーバーの代わりに、下に登録した中継サーバーだけを使います。お使いのネットワークから公開の中継サーバーに届かないときに選びます。",
    mode_desc_direct: "中継サーバーを使う経路をオフにします。共有 ID だけで受け取るにはその経路が必要なので、この設定では使えません。",
    relays_label: "中継サーバーのアドレス:",
    relays_desc: "自分で運用している中継サーバーです。https:// で始まるアドレスだけ登録できます。「自分の中継サーバー」を選んだときに使われます。",
    relay_none: "中継サーバーのアドレスはまだ登録されていません。",
    relay_placeholder: "https://relay.example.org",
    relay_add: "追加",
    relay_remove: "削除",
    err_url_empty: "先にアドレスを入力してください。",
    err_url_not_https: "アドレスは https:// で始めてください。",
    err_url_space: "アドレスに空白は使えません。",
    err_url_userinfo: "アドレスにユーザー名やパスワードは含められません。",
    err_url_host: "アドレスのサーバー名が正しくありません。",
    err_url_port: "アドレスのポート番号が正しくありません(1〜65535)。",
    err_url_query: "アドレスに ? や # は含められません。",
    err_url_dup: "このアドレスはすでに登録されています。",
    err_url_toomany: "これ以上登録できません(最大 8 件)。",
    issue_own_needs_url: "中継サーバーのアドレスを 1 件以上追加するか、ほかの接続方法を選んでください。",
    issue_retry_range: "0〜8760 の整数で時間を入力してください。",
    lan_label: "同じネットワーク内の探索:",
    lan_on: "オン",
    lan_off: "オフ",
    lan_desc: "同じローカルネットワーク内の他のコンピューターを見つけられるようにします。信頼できないネットワークではオフにしてください。",
    ca_label: "追加の証明書:",
    ca_choose: "ファイルを選ぶ...",
    ca_clear: "解除",
    ca_none: "ファイルは選ばれていません。",
    ca_desc: "安全な接続の証明書を差し替えるネットワーク向けの証明書ファイル(PEM または DER)です。システムの証明書に加えて信頼します。信頼できるファイルだけを選んでください。",
    ca_ok: "{name}: 証明書が {n} 件見つかりました。",
    ca_missing: "{name}: ファイルが存在しません。",
    ca_unreadable: "{name}: ファイルを読み込めません。",
    ca_too_large: "{name}: 証明書ファイルとしては大きすぎます。",
    ca_invalid: "{name}: 有効な証明書ファイルではありません。",
    retry_label: "再試行の期間:",
    retry_desc: "相手のコンピューターに届かないとき、送信が自動で再試行を続ける期間です。0 にすると諦めずに続けます。",
    retry_unit: "時間",
    restart_tag: "再起動後に反映",
    saved_notice: "保存しました。反映するには、Miasma を完全に閉じてからもう一度起動してください。",
    save_failed: "保存できませんでした: {err}",
    unsaved: "まだ保存していない変更があります。",
    save: "保存",
    discard: "変更を破棄",
    check_heading: "ネットワークを調べる",
    check_desc: "このネットワークから Miasma がつながる経路を順に試し、通るものを表示します。個人のデータは送りません。最長 40 秒かかり、上の保存済みの設定で調べます。",
    check_button: "ネットワークを調べる",
    check_running: "調べています... {s} 秒",
    check_cancel: "中止",
    check_cancelled: "調査を中止しました。",
    check_failed: "調査を実行できませんでした: {err}",
    col_path: "経路",
    col_target: "対象",
    col_result: "結果",
    col_reason: "理由",
    result_works: "通る",
    result_failed: "失敗",
    result_skipped: "未実施",
    summary: "通る {ok} 件、失敗 {bad} 件、未実施 {skip} 件。所要時間は {s} 秒でした。",
    measured_rtt: "往復 {ms} ミリ秒",
    measured_speed: "{kib} KiB/秒",
    no_rows: "調査の結果がありません。",
    suggest_heading: "おすすめの設定",
    suggest_none: "この結果に対する提案はありません。",
    save_report: "レポートを保存",
    report_saved: "レポートを {path} に保存しました。",
    report_failed: "レポートを保存できませんでした: {err}",
    report_file_name: "network-report.json",
};

static NET_ZH_CN: NetStrings = NetStrings {
    heading: "网络",
    intro: "Miasma 连接其他计算机的方式。更改会保存在本机，并在 Miasma 后台服务重新启动后生效。",
    load_failed: "无法读取设置文件，当前显示的是默认值。",
    mode_label: "连接方式：",
    mode_public: "公共中继服务器",
    mode_own: "我自己的中继服务器",
    mode_direct: "仅直连",
    mode_desc_public: "使用 iroh 项目提供的公共中继服务器和发现服务。这是默认设置，无需任何准备。Miasma 运行期间，本机的地址会发布到发现服务。",
    mode_desc_own: "不使用公共中继服务器，只使用下面列出的中继服务器。当你的网络无法访问公共中继服务器时请选择此项。",
    mode_desc_direct: "关闭基于中继服务器的通道。仅凭共享 ID 接收需要该通道，因此在此模式下无法使用。",
    relays_label: "中继服务器地址：",
    relays_desc: "你自己运行的中继服务器。只接受以 https:// 开头的地址。选择“我自己的中继服务器”时会使用这些地址。",
    relay_none: "尚未添加中继服务器地址。",
    relay_placeholder: "https://relay.example.org",
    relay_add: "添加",
    relay_remove: "删除",
    err_url_empty: "请先输入地址。",
    err_url_not_https: "地址必须以 https:// 开头。",
    err_url_space: "地址中不能包含空格。",
    err_url_userinfo: "地址中不能包含用户名或密码。",
    err_url_host: "地址中的服务器名称无效。",
    err_url_port: "地址中的端口无效（1 到 65535）。",
    err_url_query: "地址中不能包含 ? 或 #。",
    err_url_dup: "该地址已在列表中。",
    err_url_toomany: "列表已满（最多 8 个地址）。",
    issue_own_needs_url: "请至少添加一个中继服务器地址，或选择其他连接方式。",
    issue_retry_range: "请输入 0 到 8760 之间的整数小时数。",
    lan_label: "同一网络内发现：",
    lan_on: "开",
    lan_off: "关",
    lan_desc: "让 Miasma 找到同一局域网内的其他计算机。在不可信的网络上请关闭。",
    ca_label: "额外证书：",
    ca_choose: "选择文件...",
    ca_clear: "清除",
    ca_none: "尚未选择文件。",
    ca_desc: "适用于会替换安全连接证书的网络的证书文件（PEM 或 DER）。Miasma 会在系统证书之外额外信任它。请只选择你信任的文件。",
    ca_ok: "{name}：找到 {n} 个证书。",
    ca_missing: "{name}：文件不存在。",
    ca_unreadable: "{name}：无法读取该文件。",
    ca_too_large: "{name}：文件过大，不能作为证书文件。",
    ca_invalid: "{name}：这不是有效的证书文件。",
    retry_label: "重试时长：",
    retry_desc: "对方计算机无法连接时，发送自动持续重试的时长。0 表示永不放弃。",
    retry_unit: "小时",
    restart_tag: "重启后生效",
    saved_notice: "已保存。请完全退出 Miasma 后重新启动，更改才会生效。",
    save_failed: "无法保存：{err}",
    unsaved: "有尚未保存的更改。",
    save: "保存",
    discard: "放弃更改",
    check_heading: "检查我的网络",
    check_desc: "依次尝试 Miasma 在此网络下的各种连接方式，并显示哪些可用。不会发送任何个人数据。最多需要 40 秒，检查的是上面已保存的设置。",
    check_button: "检查我的网络",
    check_running: "正在检查... {s} 秒",
    check_cancel: "取消",
    check_cancelled: "检查已取消。",
    check_failed: "无法运行检查：{err}",
    col_path: "通道",
    col_target: "目标",
    col_result: "结果",
    col_reason: "原因",
    result_works: "可用",
    result_failed: "失败",
    result_skipped: "已跳过",
    summary: "可用 {ok} 项，失败 {bad} 项，跳过 {skip} 项。检查用时 {s} 秒。",
    measured_rtt: "往返 {ms} 毫秒",
    measured_speed: "{kib} KiB/秒",
    no_rows: "检查没有返回结果。",
    suggest_heading: "建议的设置",
    suggest_none: "针对此结果没有建议。",
    save_report: "保存报告",
    report_saved: "报告已保存到 {path}。",
    report_failed: "无法保存报告：{err}",
    report_file_name: "network-report.json",
};

/// The label of a probe group (the "path" column).
pub fn group_text(g: Group, locale: Locale) -> &'static str {
    match g {
        Group::Dns => pick(locale, "Name lookup", "名前解決", "域名解析"),
        Group::Tcp => pick(locale, "TCP", "TCP", "TCP"),
        Group::Tls => pick(locale, "Secure connection", "安全な接続", "安全连接"),
        Group::Sni => pick(
            locale,
            "Server name check",
            "サーバー名の確認",
            "服务器名称检查",
        ),
        Group::Udp => pick(locale, "UDP", "UDP", "UDP"),
        Group::Quic => pick(locale, "QUIC", "QUIC", "QUIC"),
        Group::Relay => pick(locale, "Relay", "中継", "中继"),
        Group::Lan => pick(locale, "Same network", "同じネットワーク", "同一网络"),
    }
}

/// What the probed host is for (shown with the target).
pub fn role_text(r: Role, locale: Locale) -> &'static str {
    match r {
        Role::Relay => pick(locale, "relay", "中継", "中继"),
        Role::Discovery => pick(locale, "discovery", "探索", "发现"),
        Role::Tunnel => pick(locale, "tunnel service", "トンネルサービス", "隧道服务"),
        Role::Neutral => pick(locale, "control", "対照", "对照"),
        Role::Custom => pick(locale, "extra address", "追加アドレス", "额外地址"),
        Role::Local => pick(locale, "this computer", "この端末", "本机"),
    }
}

/// Why a path works or fails, in words.
pub fn outcome_text(o: Outcome, locale: Locale) -> &'static str {
    match o {
        Outcome::Ok => pick(locale, "Works.", "通ります。", "可用。"),
        Outcome::Nxdomain => pick(
            locale,
            "The name does not exist according to this computer's name lookup.",
            "このコンピューターの名前解決では、その名前が存在しないと返されました。",
            "本机的域名解析返回该名称不存在。",
        ),
        Outcome::Timeout => pick(
            locale,
            "No answer in time.",
            "時間内に応答がありません。",
            "在规定时间内没有响应。",
        ),
        Outcome::AnswerDiffers => pick(
            locale,
            "The answer differs from the public resolvers' answer.",
            "公開リゾルバーの答えと食い違っています。",
            "与公共解析服务器的答案不一致。",
        ),
        Outcome::UdpDnsBlocked => pick(
            locale,
            "Name lookup works, but direct UDP lookups get no answer.",
            "名前解決は通りますが、UDP での直接の問い合わせには応答がありません。",
            "域名解析可用，但直接的 UDP 查询没有响应。",
        ),
        Outcome::Refused => pick(
            locale,
            "The connection was refused.",
            "接続を拒否されました。",
            "连接被拒绝。",
        ),
        Outcome::Reset => pick(
            locale,
            "The connection was reset.",
            "接続がリセットされました。",
            "连接被重置。",
        ),
        Outcome::Unreachable => pick(
            locale,
            "There is no route to the network or host.",
            "ネットワークまたはホストへの経路がありません。",
            "没有到达该网络或主机的路由。",
        ),
        Outcome::ResetInHandshake => pick(
            locale,
            "The connection was cut while the secure connection was being set up.",
            "安全な接続を確立している途中で切断されました。",
            "在建立安全连接的过程中连接被切断。",
        ),
        Outcome::NonPublicCa => pick(
            locale,
            "The certificate comes from an authority that is not a public one.",
            "証明書が公開の認証局ではない認証局から出ています。",
            "证书来自非公共的证书颁发机构。",
        ),
        Outcome::CertUntrusted => pick(
            locale,
            "The certificate was refused: it is not valid for this name.",
            "証明書が受け入れられませんでした。この名前に対して有効ではありません。",
            "证书被拒绝：它对该名称无效。",
        ),
        Outcome::SniDiffers => pick(
            locale,
            "The real server name and a neutral name are treated differently.",
            "本来のサーバー名と中立な名前で扱いが違います。",
            "真实的服务器名称与中立名称受到不同对待。",
        ),
        Outcome::UdpBlocked => pick(
            locale,
            "UDP does not get out of this network.",
            "UDP がこのネットワークの外に出ません。",
            "UDP 无法离开此网络。",
        ),
        Outcome::Failed => pick(locale, "Failed.", "失敗しました。", "失败。"),
        Outcome::Skipped => pick(
            locale,
            "Not tried: an earlier step shows it cannot work.",
            "未実施です。前の段階で通らないと分かりました。",
            "未尝试：前一步已表明它无法工作。",
        ),
    }
}

/// One suggestion. Each states what was observed and points at a control in this section;
/// none promises that a path will work.
pub fn advice_text(c: AdviceCode, locale: Locale) -> &'static str {
    match c {
        AdviceCode::RelayObserved => pick(
            locale,
            "The relay servers were reached from here, so the current connection setting works on this network.",
            "この場所から中継サーバーに届きました。現在の接続方法はこのネットワークで使えます。",
            "从此处可以访问中继服务器，当前的连接方式在此网络上可用。",
        ),
        AdviceCode::DirectUdpObserved => pick(
            locale,
            "UDP and QUIC to a relay worked, so a direct path between two computers may form. Nothing needs to be changed for that.",
            "中継サーバーへの UDP と QUIC が通りました。2 台の間に直接の経路ができる可能性があります。そのための設定変更は要りません。",
            "到中继服务器的 UDP 和 QUIC 可用，两台计算机之间可能建立直连通道。无需为此更改设置。",
        ),
        AdviceCode::UdpNotObserved => pick(
            locale,
            "UDP did not work, so transfers can only use the relay, which is slower.",
            "UDP が通りませんでした。転送は中継サーバー経由だけになり、遅くなります。",
            "UDP 不可用，传输只能经由中继服务器，速度会较慢。",
        ),
        AdviceCode::TlsInspectedTrusted => pick(
            locale,
            "The relay's certificate comes from a non-public authority (this network replaces the certificates of secure connections), and this computer already trusts it.",
            "中継サーバーの証明書は公開の認証局ではない認証局から出ています(このネットワークは安全な接続の証明書を差し替えています)。このコンピューターはその認証局をすでに信頼しています。",
            "中继服务器的证书来自非公共的证书颁发机构（此网络会替换安全连接的证书），本机已信任该机构。",
        ),
        AdviceCode::TlsInspectedUntrusted => pick(
            locale,
            "The relay's certificate comes from a non-public authority that this computer does not trust. If you trust it, choose its certificate file under \"Extra certificate\".",
            "中継サーバーの証明書が公開の認証局ではない認証局から出ていて、このコンピューターは信頼していません。信頼できる場合は、「追加の証明書」でその証明書ファイルを選んでください。",
            "中继服务器的证书来自本机不信任的非公共证书颁发机构。如果你信任它，请在“额外证书”中选择其证书文件。",
        ),
        AdviceCode::HandshakeCut => pick(
            locale,
            "The relay hosts accept connections, but the secure handshake does not complete. Choose \"My own relay\" and add a relay server you run, or try another network.",
            "中継サーバーは接続を受け付けますが、安全な接続の確立が完了しません。「自分の中継サーバー」を選んで自分で運用する中継サーバーを追加するか、別のネットワークを試してください。",
            "中继服务器可以建立连接，但安全握手无法完成。请选择“我自己的中继服务器”并添加你自己运行的中继服务器，或尝试其他网络。",
        ),
        AdviceCode::DnsProblem => pick(
            locale,
            "The relay host names did not resolve as expected here. A relay you run yourself (\"My own relay\") does not depend on the public names. The name lookup setting of this network may also need a check.",
            "この場所では中継サーバーの名前が期待どおりに引けませんでした。自分で運用する中継サーバー(「自分の中継サーバー」)なら公開の名前に頼りません。このネットワークの名前解決の設定も確認してください。",
            "此处中继服务器的名称没有按预期解析。你自己运行的中继服务器（“我自己的中继服务器”）不依赖公共名称。也请检查此网络的域名解析设置。",
        ),
        AdviceCode::DiscoveryNotObserved => pick(
            locale,
            "The public discovery service was not reached. Without it, a receiver finds senders only through the relay addresses you list.",
            "公開の探索サービスに届きませんでした。これがないと、受け取る側は登録した中継サーバーのアドレスを通してだけ送信者に届きます。",
            "无法访问公共发现服务。没有它，接收方只能通过你列出的中继服务器地址找到发送方。",
        ),
        AdviceCode::LanObserved => pick(
            locale,
            "Same-network discovery worked: with \"Same-network discovery\" on, computers on this network can find each other.",
            "同じネットワーク内の探索が動きました。「同じネットワーク内の探索」をオンにすると、同じネットワークの端末どうしが見つけ合えます。",
            "同一网络内的发现可用：打开“同一网络内发现”后，此网络中的计算机可以互相找到。",
        ),
        AdviceCode::LanNotObserved => pick(
            locale,
            "Same-network discovery did not work here, so two computers on this network may not find each other that way.",
            "同じネットワーク内の探索はここでは動きませんでした。この方法では同じネットワークの端末どうしが見つけ合えない可能性があります。",
            "此处同一网络内的发现不可用，两台同网络的计算机可能无法通过该方式互相找到。",
        ),
        AdviceCode::TunnelObserved => pick(
            locale,
            "The tunnel service was reached, so the tunnel option of the command line tool can be used from here.",
            "トンネルサービスに届きました。ここからコマンドラインツールのトンネル機能を使えます。",
            "可以访问隧道服务，因此可在此处使用命令行工具的隧道功能。",
        ),
        AdviceCode::TunnelNotObserved => pick(
            locale,
            "The tunnel service was not reached, so the tunnel option of the command line tool was not seen to work from here.",
            "トンネルサービスに届きませんでした。ここからコマンドラインツールのトンネル機能が使えることは確認できませんでした。",
            "无法访问隧道服务，因此未能确认命令行工具的隧道功能在此处可用。",
        ),
        AdviceCode::CustomEndpointObserved => pick(
            locale,
            "The extra address that was tested answered.",
            "追加で試したアドレスが応答しました。",
            "额外测试的地址有响应。",
        ),
        AdviceCode::CustomEndpointNotObserved => pick(
            locale,
            "The extra address that was tested did not answer. Its rows in the table show where it stopped.",
            "追加で試したアドレスは応答しませんでした。どこで止まったかは表の該当する行を参照してください。",
            "额外测试的地址没有响应。表中对应的行显示了它在哪一步停止。",
        ),
        AdviceCode::NothingObserved => pick(
            locale,
            "No path was seen to work. Check the connection and any proxy settings of this computer. Two computers on the same local network may still reach each other directly.",
            "通る経路は確認できませんでした。このコンピューターの接続とプロキシの設定を確認してください。同じローカルネットワークの 2 台なら、直接つながる場合があります。",
            "未发现可用的通道。请检查本机的网络连接和代理设置。同一局域网内的两台计算机仍可能直接互通。",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_network_string_exists_in_every_locale_and_keeps_its_placeholders() {
        for lang in Locale::ALL {
            let s = net_strings(lang);
            for (name, value) in s.all() {
                assert!(!value.trim().is_empty(), "{lang:?} network.{name} is empty");
            }
            for (name, value, ph) in [
                ("ca_ok", s.ca_ok, "{name}"),
                ("ca_ok", s.ca_ok, "{n}"),
                ("ca_missing", s.ca_missing, "{name}"),
                ("ca_unreadable", s.ca_unreadable, "{name}"),
                ("ca_too_large", s.ca_too_large, "{name}"),
                ("ca_invalid", s.ca_invalid, "{name}"),
                ("save_failed", s.save_failed, "{err}"),
                ("check_running", s.check_running, "{s}"),
                ("check_failed", s.check_failed, "{err}"),
                ("summary", s.summary, "{ok}"),
                ("summary", s.summary, "{bad}"),
                ("summary", s.summary, "{skip}"),
                ("summary", s.summary, "{s}"),
                ("measured_rtt", s.measured_rtt, "{ms}"),
                ("measured_speed", s.measured_speed, "{kib}"),
                ("report_saved", s.report_saved, "{path}"),
                ("report_failed", s.report_failed, "{err}"),
            ] {
                assert!(value.contains(ph), "{lang:?} network.{name} lost {ph}");
            }
        }
        let (en, ja, zh) = (
            net_strings(Locale::En),
            net_strings(Locale::Ja),
            net_strings(Locale::ZhCn),
        );
        assert_ne!(en.mode_desc_own, ja.mode_desc_own);
        assert_ne!(en.mode_desc_own, zh.mode_desc_own);
        assert_ne!(ja.mode_desc_own, zh.mode_desc_own);
    }

    #[test]
    fn zh_cn_network_texts_match_the_english_ones() {
        crate::locale::assert_translation_parity(
            "network",
            net_strings(Locale::En).all(),
            net_strings(Locale::ZhCn).all(),
        );
    }

    #[test]
    fn every_report_text_exists_in_every_locale() {
        for lang in Locale::ALL {
            for g in Group::ALL {
                assert!(!group_text(g, lang).is_empty(), "{lang:?} {g:?}");
            }
            for r in Role::ALL {
                assert!(!role_text(r, lang).is_empty(), "{lang:?} {r:?}");
            }
            for o in Outcome::ALL {
                assert!(!outcome_text(o, lang).is_empty(), "{lang:?} {o:?}");
            }
            for a in AdviceCode::ALL {
                assert!(!advice_text(a, lang).is_empty(), "{lang:?} {a:?}");
            }
        }
        // The three languages are not copies of each other.
        for o in Outcome::ALL {
            let (en, ja, zh) = (
                outcome_text(o, Locale::En),
                outcome_text(o, Locale::Ja),
                outcome_text(o, Locale::ZhCn),
            );
            assert_ne!(en, ja, "{o:?}");
            assert_ne!(en, zh, "{o:?}");
        }
        for a in AdviceCode::ALL {
            assert_ne!(
                advice_text(a, Locale::En),
                advice_text(a, Locale::Ja),
                "{a:?}"
            );
            assert_ne!(
                advice_text(a, Locale::En),
                advice_text(a, Locale::ZhCn),
                "{a:?}"
            );
        }
    }

    #[test]
    fn no_text_contains_an_emoji() {
        let is_emoji = |c: char| {
            let u = c as u32;
            (0x1F300..=0x1FAFF).contains(&u) || (0x2600..=0x27BF).contains(&u)
        };
        for lang in Locale::ALL {
            for (name, value) in net_strings(lang).all() {
                assert!(!value.chars().any(is_emoji), "{lang:?} {name}");
            }
            for a in AdviceCode::ALL {
                assert!(!advice_text(a, lang).chars().any(is_emoji));
            }
        }
    }
}
