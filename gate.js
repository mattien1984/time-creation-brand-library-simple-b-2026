(() => {
  const form=document.getElementById('entry'),field=document.getElementById('password');
  const button=document.getElementById('enter'),status=document.getElementById('status');
  const pill=document.getElementById('entry-pill'),verify=document.getElementById('verify');
  const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches;
  const decode=text=>Uint8Array.from(atob(text),c=>c.charCodeAt(0));
  const failure=(code,message)=>Object.assign(new Error(message),{code});
  const bounded=(promise,milliseconds,code,message)=>new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(failure(code,message)),milliseconds);
    promise.then(value=>{clearTimeout(timer);resolve(value);},error=>{clearTimeout(timer);reject(error);});
  });
  const progress=text=>{status.textContent=text;};
  let attempt=0,debounce,entryDownload;
  const setState=state=>{pill.dataset.state=state;pill.setAttribute('aria-busy',String(state==='checking'||state==='preparing'));};
  const isCurrent=id=>id===attempt;
  function downloadEntry(){
    if(!entryDownload)entryDownload=encryptedEntry().catch(error=>{entryDownload=undefined;throw error;});
    return entryDownload;
  }

  async function encryptedEntry() {
    const item=VAULT.files['index.html'],controller=new AbortController();
    try {
      return await bounded((async()=>{
        const response=await fetch(VAULT.base+'.sealed/'+item.file,{cache:'force-cache',signal:controller.signal});
        if(!response.ok)throw failure('NET',response.status===404?'This preview was updated. Reload this page and try again.':'The secure preview file could not be downloaded. Please try again.');
        return response.arrayBuffer();
      })(),15000,'NET','The secure preview download timed out. Please try again.');
    } catch(error) {if(!error.code)throw failure('NET','The secure preview could not connect. Please try again.');throw error;}
    finally {controller.abort();}
  }
  async function prepare() {
    if(!navigator.serviceWorker)throw failure('START','Secure preview loading is unavailable in this browser.');
    const script=new URL(VAULT.base+'sw.js?v='+VAULT.version,location.origin).href;
    let registration;
    try {registration=await bounded(navigator.serviceWorker.register(script,{scope:VAULT.base,updateViaCache:'none'}),12000,'START','Safari could not start secure preview loading. Please try again.');}
    catch(error){if(!error.code)throw failure('START','Safari could not start secure preview loading. Please try again.');throw error;}
    await new Promise((resolve,reject)=>{
      const started=Date.now();
      const check=()=>{
        if(registration.active?.scriptURL===script&&registration.active.state==='activated'){clearInterval(timer);resolve();}
        else if(Date.now()-started>=12000){clearInterval(timer);reject(failure('ACT','Safari could not activate secure preview loading. Please try again.'));}
      };
      const timer=setInterval(check,100);check();
    });
    return registration.active;
  }
  function contact(worker,payload,transfer,code) {
    return new Promise((resolve,reject)=>{
      const channel=new MessageChannel();
      const timer=setTimeout(()=>finish(failure(code,'Safari did not respond while opening the secure preview. Please try again.')),10000);
      const finish=(error,value)=>{clearTimeout(timer);channel.port1.close();error?reject(error):resolve(value);};
      channel.port1.onmessage=event=>finish(null,event.data);
      channel.port1.onmessageerror=()=>finish(failure(code,'Safari could not receive the secure preview response. Please try again.'));
      try {worker.postMessage(payload,[channel.port2,...transfer]);}
      catch {finish(failure(code,'Safari could not connect to secure preview loading. Please try again.'));}
    });
  }
  async function validate(explicit=false) {
    clearTimeout(debounce);
    if(field.readOnly||pill.dataset.state==='entering')return;
    const password=field.value,id=++attempt;
    if(!password){if(explicit){progress('Enter the preview password.');field.focus();}return;}
    setState('checking');field.removeAttribute('aria-invalid');
    if(explicit)progress('Checking password…');
    let keyBytes;
    try {
      if(!crypto.subtle)throw failure('CRYPTO','Open this preview in an updated browser.');
      // Verify locally against the encrypted entry. The password never leaves
      // the page; edits invalidate older attempts before they can unlock it.
      keyBytes=await bounded((async()=>{
        const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveBits']);
        return crypto.subtle.deriveBits({name:'PBKDF2',salt:decode(VAULT.salt),iterations:VAULT.iterations,hash:'SHA-256'},material,256);
      })(),10000,'KEY','The password check took too long. Please try again.');
      if(!isCurrent(id))return;
      const key=await bounded(crypto.subtle.importKey('raw',keyBytes,{name:'AES-GCM'},false,['decrypt']),5000,'KEY','The preview key could not be prepared. Please try again.');
      const ciphertext=(await downloadEntry()).slice(0);
      if(!isCurrent(id))return;
      try {await bounded(crypto.subtle.decrypt({name:'AES-GCM',iv:decode(VAULT.files['index.html'].iv)},key,ciphertext),5000,'CRYPTO','The password check could not finish. Please try again.');}
      catch(error){if(error.name==='OperationError')throw failure('PASSWORD','That password didn’t match. Please try again.');throw error;}
      if(!isCurrent(id))return;
      field.readOnly=true;verify.disabled=true;setState('preparing');
      progress('Preparing the library…');
      const worker=await prepare();
      const hello=await contact(worker,{type:'ping',version:VAULT.version},[],'HANDSHAKE');
      if(!hello.ok||hello.version!==VAULT.version)throw failure('VERSION','This preview was updated. Reload this page and try again.');
      const response=await contact(worker,{type:'unlock',keyBytes,ciphertext,version:VAULT.version},[keyBytes,ciphertext],'OPEN');
      if(!response.ok)throw failure(response.code||'OPEN',response.error||'The library could not open. Please try again.');
      const shouldFocus=document.activeElement===field||document.activeElement===verify;
      field.value='';field.hidden=true;verify.hidden=true;button.hidden=false;
      setState('success');progress('Password accepted.');
      if(!reduced)await new Promise(resolve=>setTimeout(resolve,780));
      setState('ready');button.disabled=false;progress('');
      if(shouldFocus)button.focus({preventScroll:true});
    } catch(error) {
      if(!isCurrent(id))return;
      setState('password');field.readOnly=false;verify.disabled=false;
      const code=error.code||'OPEN';
      // Partial typing is not an error; report a mismatch only on submission.
      progress(code==='PASSWORD'&&!explicit?'':(error.code?error.message:'The library could not open. Please try again.')+(code==='PASSWORD'?'':` (${code})`));
      if(explicit){field.setAttribute('aria-invalid',String(code==='PASSWORD'));field.focus();field.select();}
    } finally {
      if(keyBytes?.byteLength)new Uint8Array(keyBytes).fill(0);
    }
  }
  field.addEventListener('input',()=>{
    if(field.readOnly)return;
    ++attempt;clearTimeout(debounce);setState('password');progress('');field.removeAttribute('aria-invalid');
    if(field.value)debounce=setTimeout(()=>validate(false),450);
  });
  form.addEventListener('submit',event=>{event.preventDefault();validate(true);});
  button.addEventListener('click',()=>{
    if(pill.dataset.state!=='ready')return;
    setState('entering');button.disabled=true;progress('Opening the library…');
    const directGate=location.pathname===VAULT.base+'gate.html';
    // Fetch the unlocked document while preserving the requested route. The
    // library no longer contains a second intro or a dismissible auth overlay.
    if(directGate)location.replace(VAULT.base+(location.search||'')+(location.hash||''));
    else if(location.pathname.startsWith(VAULT.base))location.reload();
    else location.replace(VAULT.base);
  });
})();
