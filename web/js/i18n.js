// Miasma Web — Internationalization (EN / JA)

const translations = {
  en: {
    loading: "Loading Miasma Protocol...",
    hero_title: "Miasma Protocol",
    hero_sub: "Censorship-resistant content protection in your browser",
    hero_desc: "Split and encrypt content into shares. Reconstruct from any k-of-n shares. No server required.",
    dissolve: "Dissolve",
    dissolve_desc: "Encrypt and split content into protected shares",
    retrieve: "Retrieve",
    retrieve_desc: "Reconstruct content from collected shares",
    stored_shares: "Stored shares",
    known_mids: "Known MIDs",
    text: "Text",
    file: "File",
    enter_text: "Enter text to dissolve...",
    drop_file: "Drop a file here or tap to select",
    advanced_params: "Advanced Parameters",
    param_k_hint: "(minimum shares to recover)",
    param_n_hint: "(total shares generated)",
    dissolve_action: "Dissolve",
    processing: "Processing...",
    dissolved: "Content Dissolved",
    copy: "Copy",
    save_locally: "Save to Browser",
    export_file: "Export .miasma",
    enter_mid: "Enter MID",
    share_sources: "Share Sources",
    local_storage: "Local Storage",
    local_desc: "Shares saved in this browser",
    import_shares: "Import Shares",
    import_file: "Import .miasma",
    paste_json: "Paste JSON",
    paste_shares: "Paste Share Data",
    cancel: "Cancel",
    import: "Import",
    shares_collected: "Shares collected",
    retrieve_action: "Retrieve",
    retrieved: "Content Retrieved",
    binary_content: "Binary content",
    download: "Download",
    settings: "Settings",
    storage_title: "Storage",
    storage_used: "Storage used",
    clear_all_shares: "Clear All Shares",
    language_title: "Language",
    about_title: "About",
    about_desc: "Miasma Web is a browser-based client for the Miasma Protocol. All cryptographic operations run locally in WebAssembly. No data is sent to any server.",
    security_title: "Security Notice",
    security_notice_1: "This is a beta product. It has not been independently audited.",
    security_notice_2: "Browser memory management differs from native apps. Key material may persist in memory longer than expected.",
    security_notice_3: "IndexedDB storage is not encrypted. Shares are individually meaningless (require k-of-n), but physical device access could expose them.",
    security_notice_4: "Do not use for highly sensitive content.",
    copied: "Copied!",
    saved: "Shares saved to browser",
    exported: "Shares exported",
    imported: "shares imported",
    cleared: "All shares cleared",
    error_no_input: "No input provided",
    error_invalid_params: "Invalid parameters: k must be < n",
    error_no_mid: "Please enter a MID",
    error_insufficient: "Not enough shares",
    error_retrieve: "Retrieval failed",
    error_file_too_large: "File too large (max ~100 MB)",
    error_invalid_mid_format: "MID must start with 'miasma:'",
    error_dissolve_failed: "Dissolution failed",
    error_import_failed: "Failed to import shares",
    error_parse_failed: "Failed to parse share data",
    confirm_clear: "Delete all stored shares? This cannot be undone.",
    install_hint: "Add to Home Screen for offline use",
  },
  ja: {
    loading: "Miasma Protocol を読み込み中...",
    hero_title: "Miasma Protocol",
    hero_sub: "検閲耐性のあるコンテンツ保護をブラウザで",
    hero_desc: "コンテンツを暗号化・分割してシェアに変換。k-of-nのシェアから復元可能。サーバー不要。",
    dissolve: "Dissolve（分散）",
    dissolve_desc: "コンテンツを暗号化・分割してシェアを生成",
    retrieve: "Retrieve（復元）",
    retrieve_desc: "収集したシェアからコンテンツを復元",
    stored_shares: "保存済みシェア",
    known_mids: "既知のMID",
    text: "テキスト",
    file: "ファイル",
    enter_text: "分散するテキストを入力...",
    drop_file: "ファイルをドロップまたはタップして選択",
    advanced_params: "詳細パラメータ",
    param_k_hint: "（復元に必要な最小シェア数）",
    param_n_hint: "（生成されるシェア総数）",
    dissolve_action: "Dissolve 実行",
    processing: "処理中...",
    dissolved: "コンテンツを分散しました",
    copy: "コピー",
    save_locally: "ブラウザに保存",
    export_file: ".miasma エクスポート",
    enter_mid: "MIDを入力",
    share_sources: "シェアソース",
    local_storage: "ローカルストレージ",
    local_desc: "このブラウザに保存されたシェア",
    import_shares: "シェアをインポート",
    import_file: ".miasma インポート",
    paste_json: "JSONを貼り付け",
    paste_shares: "シェアデータを貼り付け",
    cancel: "キャンセル",
    import: "インポート",
    shares_collected: "収集済みシェア",
    retrieve_action: "復元実行",
    retrieved: "コンテンツを復元しました",
    binary_content: "バイナリコンテンツ",
    download: "ダウンロード",
    settings: "設定",
    storage_title: "ストレージ",
    storage_used: "使用容量",
    clear_all_shares: "全シェアを削除",
    language_title: "言語",
    about_title: "概要",
    about_desc: "Miasma WebはMiasma Protocolのブラウザ版クライアントです。全ての暗号処理はWebAssemblyでローカル実行されます。データはサーバーに送信されません。",
    security_title: "セキュリティに関する注意",
    security_notice_1: "本製品はベータ版です。独立したセキュリティ監査は未実施です。",
    security_notice_2: "ブラウザのメモリ管理はネイティブアプリと異なります。鍵素材がメモリに想定より長く残る可能性があります。",
    security_notice_3: "IndexedDBのストレージは暗号化されていません。シェアは個別には無意味（k-of-n必要）ですが、デバイスへの物理アクセスで露出する可能性があります。",
    security_notice_4: "高度に機密性の高いコンテンツには使用しないでください。",
    copied: "コピーしました",
    saved: "シェアをブラウザに保存しました",
    exported: "シェアをエクスポートしました",
    imported: "件のシェアをインポートしました",
    cleared: "全シェアを削除しました",
    error_no_input: "入力がありません",
    error_invalid_params: "パラメータが無効です: k < n である必要があります",
    error_no_mid: "MIDを入力してください",
    error_insufficient: "シェアが不足しています",
    error_retrieve: "復元に失敗しました",
    error_file_too_large: "ファイルが大きすぎます（最大約100MB）",
    error_invalid_mid_format: "MIDは 'miasma:' で始まる必要があります",
    error_dissolve_failed: "分散処理に失敗しました",
    error_import_failed: "シェアのインポートに失敗しました",
    error_parse_failed: "シェアデータの解析に失敗しました",
    confirm_clear: "保存された全シェアを削除しますか？この操作は元に戻せません。",
    install_hint: "ホーム画面に追加してオフラインで使用",
  }
};

let currentLang = localStorage.getItem('miasma-lang') || 'en';

export function t(key) {
  return translations[currentLang]?.[key] || translations.en[key] || key;
}

export function getLang() {
  return currentLang;
}

export function setLang(lang) {
  if (translations[lang]) {
    currentLang = lang;
    localStorage.setItem('miasma-lang', lang);
    applyTranslations();
  }
}

export function applyTranslations() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    const text = t(key);
    if (text) el.textContent = text;
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    const text = t(key);
    if (text) el.placeholder = text;
  });
  // Update lang button
  const btn = document.getElementById('btn-lang');
  if (btn) btn.textContent = currentLang.toUpperCase();
  // Update lang button active states
  document.querySelectorAll('.lang-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.lang === currentLang);
  });
}
