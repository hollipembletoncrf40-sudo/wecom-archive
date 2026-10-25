/* lock.js — 前端解密门禁
   数据文件在服务器上全为 AES-256-GCM 密文；只有输入正确口令才会在本地解出 JSON。 */
(function(){
  var META=null, KEY=null, META_URL='data/meta.json';

  function b64ToBytes(b64){var s=atob(b64),a=new Uint8Array(s.length);for(var i=0;i<s.length;i++)a[i]=s.charCodeAt(i);return a;}
  function bytesToB64(b){var s='';for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s);}
  function hexToBytes(h){var a=new Uint8Array(h.length/2);for(var i=0;i<a.length;i++)a[i]=parseInt(h.substr(i*2,2),16);return a;}

  async function deriveKey(pw){
    var base=await crypto.subtle.importKey('raw',new TextEncoder().encode(pw),'PBKDF2',false,['deriveKey']);
    return crypto.subtle.deriveKey(
      {name:'PBKDF2',salt:hexToBytes(META.salt),iterations:META.iters,hash:'SHA-256'},
      base,{name:'AES-GCM',length:256},false,['decrypt']);
  }
  async function decBuf(buf,key){
    var u=new Uint8Array(buf), iv=u.subarray(0,12), ct=u.subarray(12);
    var pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:iv},key,ct);
    return new TextDecoder().decode(pt);
  }
  async function fetchEnc(path){
    var r=await fetch(path+'.enc',{cache:'force-cache'});
    if(!r.ok) throw new Error('HTTP '+r.status+' · '+path);
    return r.arrayBuffer();
  }

  window.__LOAD__ = async function(path){
    if(!KEY) throw new Error('未解锁');
    var txt=await decBuf(await fetchEnc(path),KEY);
    return JSON.parse(txt);
  };

  /* ---------- 门禁 UI ---------- */
  function gate(){
    var el=document.createElement('div'); el.id='lockGate';
    el.innerHTML=`<div class="lockbox">
      <div class="lbadge">● ENCRYPTED ARCHIVE</div>
      <h2>企业微信群聊档案</h2>
      <p class="lsub">本档含内部生产数据，全站内容以 AES-256-GCM 加密存放。<br>请输入访问口令解锁。</p>
      <input id="lockPw" type="password" placeholder="访问口令" autocomplete="current-password" spellcheck="false">
      <button id="lockBtn">解 锁</button>
      <div class="lerr" id="lockErr"></div>
      <div class="lfoot">口令由数据持有者设置 · 本站不保存口令，只在浏览器内存中派生密钥</div>
    </div>`;
    var st=document.createElement('style');
    st.textContent=`
    #lockGate{position:fixed;inset:0;z-index:9999;background:#03040a;display:flex;align-items:center;justify-content:center;padding:24px;
      background-image:radial-gradient(60% 50% at 20% 10%,rgba(0,229,255,.12),transparent 70%),radial-gradient(50% 45% at 85% 85%,rgba(255,45,149,.12),transparent 70%)}
    .lockbox{width:100%;max-width:420px;border:1px solid rgba(120,180,255,.16);background:rgba(10,16,30,.72);padding:38px 32px;text-align:center;
      box-shadow:0 30px 90px -30px rgba(0,229,255,.35)}
    .lbadge{font-size:10px;letter-spacing:.26em;color:#00e5ff;margin-bottom:18px}
    .lockbox h2{font-size:21px;font-weight:800;letter-spacing:-.01em;color:#fff;margin-bottom:12px}
    .lsub{font-size:12px;line-height:1.85;color:#69788a;margin-bottom:22px}
    #lockPw{width:100%;background:rgba(255,255,255,.05);border:1px solid rgba(120,180,255,.18);color:#eaf2ff;padding:12px 14px;font-size:13px;
      outline:none;font-family:inherit;text-align:center;letter-spacing:.12em}
    #lockPw:focus{border-color:rgba(0,229,255,.55);box-shadow:0 0 0 2px rgba(0,229,255,.08)}
    #lockBtn{margin-top:12px;width:100%;padding:12px;background:rgba(0,229,255,.09);border:1px solid rgba(0,229,255,.4);color:#00e5ff;
      font-size:13px;letter-spacing:.2em;cursor:pointer;font-family:inherit;transition:.2s}
    #lockBtn:hover{background:rgba(0,229,255,.2)}
    #lockBtn:disabled{opacity:.5;cursor:wait}
    .lerr{min-height:18px;margin-top:12px;font-size:11.5px;color:#ff2d95;letter-spacing:.02em}
    .lfoot{margin-top:16px;font-size:10px;color:#3b4757;line-height:1.7}`;
    document.head.appendChild(st); document.body.appendChild(el);
    var pw=document.getElementById('lockPw'), btn=document.getElementById('lockBtn'), err=document.getElementById('lockErr');
    setTimeout(function(){pw.focus();},80);

    async function attempt(){
      var v=pw.value; if(!v) return;
      btn.disabled=true; btn.textContent='校验中…'; err.textContent='';
      var t0=performance.now();
      try{
        var key=await deriveKey(v);
        var probe=await decBuf(await fetchEnc('data/probe'),key);   // 校验口令
        if(probe!=='wecom-ok') throw new Error('bad');
        KEY=key;
        try{ sessionStorage.setItem('wecom_key',bytesToB64(new Uint8Array(await crypto.subtle.exportKey('raw',key)))); }catch(e){}
        el.remove(); st.remove();
        window.__unlockResolve();
      }catch(e){
        err.textContent='口令错误，或数据尚未生成';
        btn.disabled=false; btn.textContent='解 锁'; pw.select();
        console.warn(e);
      }
    }
    btn.onclick=attempt;
    pw.addEventListener('keydown',function(e){ if(e.key==='Enter') attempt(); });
  }

  window.__READY__ = new Promise(function(res){ window.__unlockResolve=res; });

  (async function(){
    try{ META=await (await fetch(META_URL,{cache:'no-store'})).json(); }
    catch(e){ document.getElementById('metaLine').innerHTML='<span style="color:#ff2d95">缺少 data/meta.json —— 请先运行 build-public.mjs 生成加密数据</span>'; return; }
    var saved=null;
    try{ saved=sessionStorage.getItem('wecom_key'); }catch(e){}
    if(saved){
      try{
        var key=await crypto.subtle.importKey('raw',b64ToBytes(saved),{name:'AES-GCM'},false,['decrypt']);
        var p=await decBuf(await fetchEnc('data/probe'),key);
        if(p==='wecom-ok'){ KEY=key; window.__unlockResolve(); return; }
      }catch(e){ try{sessionStorage.removeItem('wecom_key');}catch(_){} }
    }
    gate();
  })();
})();
