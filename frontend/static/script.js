const $=s=>document.querySelector(s);
const api=(u,b)=>fetch(u,b===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(r=>r.json());
let since=-1,D={incidents:[],stats:{}},sel=null,filter='All',mute=false,openUntil=0,ac,ft,tt,seen=new Set();const OT=document.title;
const LC={Critical:'c',High:'h',Medium:'m',Low:'l'},COL={Critical:'#ff3b4e',High:'#fb923c',Medium:'#facc15',Low:'#34d399'};

/* ---------- boot intro ---------- */
const BL=['[ OK ] Initializing ThreatLens core','[ OK ] Loading risk-scoring engine','[ OK ] Connecting to alert feed','[ OK ] Mapping asset inventory','[ OK ] Calibrating AI copilot','>> SYSTEM READY'];let bi=0;
(function bt(){if(bi<BL.length){$('#bl').textContent+=BL[bi++]+'\n';$('#pb').style.width=bi/BL.length*100+'%';setTimeout(bt,450)}else $('#enter').hidden=false})();
$('#enter').onclick=()=>{ac=new AudioContext;$('#boot').classList.add('off');schedule()};
/* alarm schedule: alerts live for the first minute after entering, then once every 3 minutes */
function schedule(){const fire=ms=>{openUntil=Date.now()+ms;api('/api/simulate',{})};setTimeout(()=>fire(60000),3000);setInterval(()=>fire(15000),180000)}

/* ---------- polling + render ---------- */
async function poll(){try{const d=await api('/api/state?since='+since);since=d.seq;D=d;$('#off').hidden=true;render();d.events.forEach(e=>e.kind=='alert'?arc(e):Date.now()<openUntil&&alarm(e.incident))}catch(e){$('#off').hidden=false}}
setInterval(poll,1500);poll();
let lastSig=null;
function render(){
  const s=D.stats;$('#sA').textContent=s.alerts;$('#sI').textContent=s.incidents;$('#sC').textContent=s.critical;$('#sN').textContent=s.noise+'%';
  $('#cl').innerHTML=D.clusters.length?'<b>⛓ Likely incident clusters detected:</b>'+D.clusters.map(c=>`<span class="tag">${c.id} · ${c.label}</span>`).join(''):'';
  $('#rc').innerHTML='<b>Normalised alert stream:</b>'+D.recent.map(a=>`<span class="tag">${a.source} → ${a.type} · ${a.asset} · sev ${a.sev}</span>`).join('');
  $('#tb').innerHTML=D.incidents.filter(i=>filter=='All'||i.level==filter).slice(0,12).map(i=>{const c=LC[i.level],nw=!seen.has(i.id);seen.add(i.id);
    const bd=(i.cluster?`<em>⛓ ${i.cluster}</em>`:'')+(i.coll?'<em>📉→📈 pattern</em>':'')+(i.capped?'<em>🛡 capped</em>':'')+(i.override?'<em>✎ analyst</em>':'');
    return`<tr class="${c}${i.status==2?' done':''}${sel==i.id?' sel':''}${nw?' nw':''}" data-id="${i.id}"><td><span class="pill ${c}">${i.level}</span></td><td>${i.type}<small>#${i.id} · ${i.asset}</small>${bd}</td><td>×${i.n}<small>${i.srcs} source${i.srcs>1?'s':''}</small></td><td><span class="meter"><u style="width:${i.eff}%"></u></span>${i.eff}</td><td><button data-s="${i.id}">${i.status_name}</button></td></tr>`}).join('');
  const i=D.incidents.find(x=>x.id==sel);if(i){const sg=JSON.stringify([sel,i.score,i.eff,i.status,i.override,i.n,i.cluster]);if(sg!==lastSig)explain(0)}
}
function explain(typing){
  const i=D.incidents.find(x=>x.id==sel);if(!i)return;lastSig=JSON.stringify([sel,i.score,i.eff,i.status,i.override,i.n,i.cluster]);
  const b=(n,v,m)=>`<div class="b2"><span>${n}</span><span class="meter"><u style="width:${Math.min(100,v*(m||1))}%"></u></span><b>${v}</b></div>`;
  $('#ai').innerHTML=`<h3>🧠 Why "${i.level}"? <small>#${i.id}</small></h3>${b('Severity',i.sev)+b('Asset value',i.ast)+b('Biz impact',i.imp)+b('Confidence',i.conf)+b('Grouping +',i.grp,10)+b('Cluster +',i.chain+i.coll,3)}<p id="why"></p><p class="act">▶ ${i.action}.</p><div class="ctl"><select id="pr"><option value="">Auto priority</option>${['Critical','High','Medium','Low'].map(l=>`<option ${i.override==l?'selected':''}>${l}</option>`).join('')}</select><select id="st">${['New','Investigating','Resolved'].map((l,k)=>`<option value="${k}" ${i.status==k?'selected':''}>${l}</option>`).join('')}</select></div>`;
  clearInterval(tt);if(!typing)return $('#why').textContent=i.reason;
  let k=0;tt=setInterval(()=>{$('#why').textContent=i.reason.slice(0,++k);if(k>=i.reason.length)clearInterval(tt)},12);
}
$('#ai').onchange=async e=>{if(e.target.id=='pr')await api(`/api/incidents/${sel}/priority`,{level:e.target.value});if(e.target.id=='st')await api(`/api/incidents/${sel}/status`,{status:+e.target.value});poll()};
$('#demo').onclick=async()=>{openUntil=Date.now()+8000;sel=null;await api('/api/load-demo',{});$('#feed').textContent='📡 Live feed: OFF';await poll()};
$('#top1').onclick=async()=>{const i=D.incidents.find(x=>x.status<2);if(!i)return;await api(`/api/incidents/${i.id}/status`,{status:1});sel=i.id;await poll();explain(1);$('#console').scrollIntoView()};
$('#feed').onclick=async e=>{const r=await api('/api/feed',{});e.target.textContent='📡 Live feed: '+(r.on?'ON':'OFF')};
$('#tb').onclick=async e=>{const tr=e.target.closest('tr'),bt=e.target.closest('[data-s]');if(!tr)return;
  if(bt){const i=D.incidents.find(x=>x.id==bt.dataset.s);await api(`/api/incidents/${i.id}/status`,{status:(i.status+1)%3});poll()}
  else{sel=+tr.dataset.id;render();explain(1)}};
$('#fl').onclick=e=>{if(!e.target.classList.contains('chp'))return;document.querySelectorAll('.chp').forEach(c=>c.classList.remove('on'));e.target.classList.add('on');filter=e.target.textContent;render()};

/* ---------- HIGH ALERT ---------- */
function siren(){if(mute||!ac)return;try{ac.resume();const o=ac.createOscillator(),g=ac.createGain(),t=ac.currentTime;o.type='sawtooth';g.gain.value=.07;o.connect(g);g.connect(ac.destination);for(let k=0;k<6;k++)o.frequency.setValueAtTime(k%2?620:880,t+k*.5);o.start();o.stop(t+3)}catch(e){}}
function alarm(i){
  $('#am').textContent=`${i.type} on ${i.asset} — risk score ${i.score}/100`;
  $('#alarm').classList.add('on');document.body.classList.add('red');siren();navigator.vibrate&&navigator.vibrate([300,150,300]);
  if(window.Notification&&Notification.permission=='granted')new Notification('🚨 ThreatLens HIGH ALERT',{body:$('#am').textContent});
  let f=0;clearInterval(ft);ft=setInterval(()=>document.title=f++%2?OT:'🚨 CRITICAL ALERT',700);
}
$('#ack').onclick=()=>{$('#alarm').classList.remove('on');document.body.classList.remove('red');clearInterval(ft);document.title=OT};
$('#sim').onclick=()=>{openUntil=Date.now()+8000;api('/api/simulate',{})};
$('#storm').onclick=()=>{openUntil=Date.now()+8000;api('/api/burst',{n:200})};
$('#mute').onclick=e=>{mute=!mute;e.target.textContent=mute?'🔇 Sound off':'🔊 Sound on'};
$('#notif').onclick=()=>window.Notification&&Notification.requestPermission();

/* ---------- attack map ---------- */
const PL=[[[-168,66],[-120,72],[-80,72],[-55,50],[-80,25],[-98,16],[-118,30],[-130,50]],[[-80,10],[-50,-2],[-35,-8],[-55,-35],[-72,-55],[-78,-10]],[[-10,36],[-10,58],[30,70],[40,50],[30,36]],[[-17,20],[-5,36],[35,32],[51,12],[40,-15],[20,-35],[10,-5],[-10,5]],[[40,36],[40,70],[100,76],[170,66],[140,40],[122,22],[105,8],[78,6],[68,24],[50,28]],[[114,-22],[130,-12],[152,-12],[153,-30],[135,-35],[115,-34]]];
const X=lo=>(lo+180)/360*720,Y=la=>(80-la)/140*300,NS='http://www.w3.org/2000/svg';
const inside=(p,x,y)=>{let c=0;for(let i=0,j=p.length-1;i<p.length;j=i++){const[a,b]=p[i],[d,e]=p[j];if((b>y)!=(e>y)&&x<(d-a)*(y-b)/(e-b)+a)c=!c}return c};
let dots='';for(let la=75;la>-58;la-=3)for(let lo=-170;lo<180;lo+=3)if(PL.some(p=>inside(p,lo,la)))dots+=`M${X(lo)} ${Y(la)}h0`;
$('#map').innerHTML=`<path d="${dots}" stroke="#22d3ee" stroke-opacity=".35" stroke-width="2.4" stroke-linecap="round"/><g id="arcs"></g><circle cx="${X(77.6)}" cy="${Y(12.9)}" r="5" fill="#22d3ee"><animate attributeName="r" values="4;11;4" dur="2s" repeatCount="indefinite"/></circle><text x="${X(77.6)+10}" y="${Y(12.9)+4}" fill="#22d3ee" font-size="11" font-family="JetBrains Mono">YOUR SOC</text>`;
function arc(e){const x1=X(e.lon),y1=Y(e.lat),x2=X(77.6),y2=Y(12.9),mx=(x1+x2)/2,my=Math.min(y1,y2)-Math.abs(x1-x2)*.28,c=COL[e.level],g=document.createElementNS(NS,'g');
  g.innerHTML=`<path class="arc" pathLength="100" d="M${x1} ${y1}Q${mx} ${my} ${x2} ${y2}" stroke="${c}"/><circle cx="${x1}" cy="${y1}" r="3" fill="${c}"><animate attributeName="r" values="2;9;2" dur="1.2s" repeatCount="3"/></circle>`;
  $('#arcs').appendChild(g);setTimeout(()=>g.remove(),4600)}

/* ---------- AI copilot ---------- */
const cm=$('#cm');
const say=(t,w)=>{const d=document.createElement('div');d.className='mg '+w;d.textContent=t;cm.appendChild(d);cm.scrollTop=cm.scrollHeight;return d};
async function ask(t){if(!t.trim())return;say(t,'me');$('#cin').value='';const d=say('…','bot');
  try{const r=await api('/api/chat',{message:t});d.textContent='';let k=0;const s=r.reply;const iv=setInterval(()=>{d.textContent=s.slice(0,k+=3);cm.scrollTop=cm.scrollHeight;if(k>=s.length)clearInterval(iv)},14)}catch(e){d.textContent='Backend offline.'}}
$('#cbtn').onclick=()=>{$('#chat').classList.toggle('on');if(!cm.children.length)say("Hi, I'm ThreatLens Copilot 👋 Ask me what to investigate first, or explain any incident by its #ID.",'bot')};
$('#cx').onclick=()=>$('#chat').classList.remove('on');$('#cs').onclick=()=>ask($('#cin').value);$('#cin').onkeydown=e=>e.key=='Enter'&&ask(e.target.value);
document.querySelectorAll('.qs button').forEach(b=>b.onclick=()=>ask(b.textContent));

/* ---------- effects ---------- */
addEventListener('scroll',()=>$('#prog').style.width=scrollY/(document.body.scrollHeight-innerHeight)*100+'%');
document.addEventListener('mousemove',e=>$('#glow').style.transform=`translate(${e.clientX-200}px,${e.clientY-200}px)`);
const ph=['Act on what matters.','Cut the noise.','Stop the breach first.'];let pi=0,ci=0,dl=0;
(function ty(){const s=ph[pi];ci+=dl?-1:1;$('#ty').textContent=s.slice(0,ci);let d=dl?35:70;if(!dl&&ci==s.length){dl=1;d=1400}else if(dl&&!ci){dl=0;pi=(pi+1)%ph.length;d=300}setTimeout(ty,d)})();
const cv=$('#bg'),g2=cv.getContext('2d');let W,H,P=[];
function rs(){W=cv.width=innerWidth;H=cv.height=innerHeight;P=Array.from({length:Math.min(70,W/18|0)},()=>({x:Math.random()*W,y:Math.random()*H,vx:Math.random()-.5,vy:Math.random()-.5}))}rs();addEventListener('resize',rs);
(function f(){g2.clearRect(0,0,W,H);P.forEach((p,i)=>{p.x=(p.x+p.vx*.4+W)%W;p.y=(p.y+p.vy*.4+H)%H;g2.fillStyle='#22d3ee99';g2.fillRect(p.x,p.y,2,2);
  for(let j=i+1;j<P.length;j++){const q=P[j],d=Math.hypot(p.x-q.x,p.y-q.y);if(d<130){g2.strokeStyle=`rgba(34,211,238,${.18*(1-d/130)})`;g2.beginPath();g2.moveTo(p.x,p.y);g2.lineTo(q.x,q.y);g2.stroke()}}});requestAnimationFrame(f)})();
  /* ====================== ThreatLens AI SUITE (end of script.js) ====================== */
(()=>{
const H=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
document.querySelector('nav div').insertAdjacentHTML('beforeend','<a href="#aic">AI Center</a>');
const sec=document.createElement('section');sec.id='aic';
sec.innerHTML=`<div class="wrap"><h2>AI Command Center</h2><p class="sub">Predictive, autonomous and explainable AI on top of the risk engine. Uses Claude when an API key is set, and works fully offline without one.</p>
<div class="axg">
<div class="axc"><h3>📈 Anomaly radar</h3><div id="an"></div></div>
<div class="axc"><h3>🤖 Autopilot</h3><p class="axm">Auto-runs safe containment steps on new Critical incidents. Risky steps still wait for human approval.</p><button class="btn ghost" id="apb">Autopilot: OFF</button><div class="axlog" id="aplog"></div></div>
<div class="axc wide"><h3>🎯 Threat actor profiles</h3><div id="atk"></div></div>
<div class="axc wide"><h3>🧾 Executive briefing</h3><button class="btn" id="brb">Generate briefing</button><pre class="brief" id="brt"></pre></div>
<div class="axc wide"><h3>🔬 Incident intelligence <small id="iit"></small></h3><div id="iib"><p class="axm">Select an incident in the Live Risk Console, or:</p><button class="btn ghost" id="iitop">Analyse top incident</button></div></div>
</div></div>`;
$('#mapsec').before(sec);

/* overview: anomaly, attackers, autopilot */
async function ov(){try{const o=await api('/api/ai/overview'),a=o.anomaly,mx=Math.max(1,...a.series);
  const col=a.status=='Surge'?'#ff3b4e':a.status=='Elevated'?'#facc15':'#22d3ee',pc=a.status=='Surge'?'c':a.status=='Elevated'?'m':'l';
  const pts=a.series.map((v,i)=>`${(i/(a.series.length-1)*300).toFixed(1)},${(50-v/mx*46).toFixed(1)}`).join(' ');
  $('#an').innerHTML=`<svg viewBox="0 0 300 54" class="spark"><polyline points="${pts}" fill="none" stroke="${col}" stroke-width="2"/></svg><p><span class="pill ${pc}">${a.status}</span> z-score <b>${a.z}</b> · ${a.rate} alerts/min vs baseline ${a.base}/min</p><p class="axm">${H(a.note)}</p>`;
  $('#atk').innerHTML=o.attackers.length?`<div class="tw"><table><thead><tr><th>Source IP</th><th>Origin</th><th>Profile</th><th>Alerts / Incidents</th><th>Threat</th><th>Action</th></tr></thead><tbody>${o.attackers.map(x=>`<tr><td>${H(x.ip)}</td><td>${H(x.origin)}</td><td>${H(x.profile)}</td><td>${x.alerts} / ${x.incidents}</td><td><span class="meter"><u style="width:${x.score}%"></u></span>${x.score}</td><td>${H(x.action)}</td></tr>`).join('')}</tbody></table></div>`:'<p class="axm">No attacker IPs yet.</p>';
  $('#apb').textContent='Autopilot: '+(o.autopilot?'ON':'OFF');
  $('#aplog').innerHTML=o.log.map(l=>`<div>${H(l)}</div>`).join('')||'<div class="axm">No automated actions yet.</div>';
 }catch(e){}}
setInterval(ov,3000);ov();
$('#apb').onclick=async()=>{await api('/api/ai/autopilot',{});ov()};

/* executive briefing */
$('#brb').onclick=async()=>{const b=$('#brb'),el=$('#brt');b.disabled=true;b.textContent='Analysing…';
 try{const o=await api('/api/ai/brief',{}),s=`[${o.engine} · posture ${o.posture}]\n\n`+o.text;let k=0;el.textContent='';clearInterval(el._t);el._t=setInterval(()=>{el.textContent=s.slice(0,k+=4);if(k>=s.length)clearInterval(el._t)},12)}
 catch(e){el.textContent='Backend offline.'}
 b.disabled=false;b.textContent='Generate briefing'};

/* incident intelligence follows the selected incident */
let shown=null;
async function intel(id){let o;try{o=await api('/api/ai/incident/'+id)}catch(e){return}
 if(o.error){$('#iib').innerHTML='<p class="axm">Incident not found.</p>';return}
 $('#iit').textContent='#'+o.id;
 $('#iib').innerHTML=`<div class="axi">
 <div><h4>Classification</h4><p><span class="pill ${LC[o.level]}">${o.level}</span> ${H(o.type)} on ${H(o.asset)}</p>${o.mitre.map(m=>`<span class="tag">${H(m.tactic)} · ${m.id} ${H(m.name)}</span>`).join('')}
  <div class="axb"><span>False-positive likelihood</span><span class="meter"><u style="width:${o.fp}%"></u></span><b>${o.fp}%</b></div>
  ${o.at_risk.length?`<h4 style="margin-top:14px">Crown jewels at risk next</h4>${o.at_risk.map(a=>`<span class="tag">⚠ ${H(a)}</span>`).join('')}`:''}</div>
 <div><h4>Predicted next moves</h4>${o.predictions.length?o.predictions.map(p=>`<div class="axb"><span>${H(p.type)}<small>${p.mitre} · ~${p.eta_min} min</small></span><span class="meter"><u style="width:${p.prob}%"></u></span><b>${p.prob}%</b></div>`).join(''):'<p class="axm">Final stage of the chain, nothing further predicted.</p>'}</div>
 <div><h4>Response playbook</h4>${o.playbook.map(s=>`<div class="axs"><span class="tag">${s.mode=='auto'?'AUTO':'APPROVAL'}</span>${H(s.step)}</div>`).join('')}
  <div class="ctl"><button class="btn" data-run="auto">▶ Run safe steps</button><button class="btn ghost" data-run="all">✅ Approve all</button></div></div></div><pre class="brief" id="runlog"></pre>`}
setInterval(()=>{if(sel!==null&&sel!==shown){shown=sel;intel(sel)}},800);
$('#iib').onclick=async e=>{
 if(e.target.id=='iitop'){const i=D.incidents.find(x=>x.status<2);if(i){sel=i.id;render()}return}
 const b=e.target.closest('[data-run]');if(!b||shown==null)return;
 const r=await api(`/api/ai/playbook/${shown}/run`,{approve:b.dataset.run=='all'});
 $('#runlog').textContent=r.log.join('\n');poll();ov()};

/* copilot: new quick questions + voice (Chrome) */
['Executive briefing','Predict next attack step','Who is attacking us?','Any anomalies?','Which alerts are false positives?'].forEach(t=>{
 const b=document.createElement('button');b.textContent=t;b.onclick=()=>ask(t);document.querySelector('.qs').appendChild(b)});
async function voiceAsk(t){say(t,'me');const d=say('…','bot');
 try{const r=await api('/api/chat',{message:t});d.textContent=r.reply;speechSynthesis.cancel();
  const u=new SpeechSynthesisUtterance(r.reply.replace(/[•#→▶]/g,' '));u.rate=1.05;speechSynthesis.speak(u)}
 catch(e){d.textContent='Backend offline.'}}
const SR=window.SpeechRecognition||window.webkitSpeechRecognition;
if(SR){const mic=document.createElement('button');mic.textContent='🎤';mic.title='Talk to Copilot';$('#cs').before(mic);
 mic.onclick=()=>{const r=new SR();r.lang='en-IN';r.onstart=()=>mic.textContent='🔴';r.onend=()=>mic.textContent='🎤';
  r.onresult=e=>voiceAsk(e.results[0][0].transcript);r.start()}}
})();
/* ====================== ZERO-TRUST STREAM ACCESS (end of script.js) ====================== */
(()=>{
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const sec=document.createElement('section');sec.id='zt';
sec.innerHTML=`<div class="wrap"><h2>Zero-Trust Stream Access</h2><p class="sub">Sensitive video and log streams open only when <b>role</b>, <b>network location</b> and <b>exact physical location</b> all pass. The server re-checks every 1.5 seconds.</p>
<div class="ztg"><div class="ztc" id="ztl"></div><div class="ztc" id="ztx"></div><div class="ztc wide"><div class="ztm" id="ztm"></div></div><div class="ztc wide" id="ztv" hidden></div><div class="ztc wide" id="zta" hidden></div></div></div>`;
const ref=$('#aic');ref?ref.after(sec):$('#mapsec').before(sec);
document.querySelector('nav div').insertAdjacentHTML('beforeend','<a href="#zt">Secure Streams</a>');
let O=null,gps=null,opened=null,vt=0,seq=0,loglines=[],vmode='',lastWho=null,lastSig='';

$('#ztx').innerHTML=`<h3>📡 Your access context</h3>
<div class="ztr"><span>Network</span><b id="znz">…</b><small id="zip"></small></div>
<div class="ztr ztd"><span>Simulate</span><select id="ztn"><option value="">Real network</option><option>SOC LAN</option><option>Corp VPN</option><option>Public internet</option></select></div>
<div class="ztr"><span>Location</span><b id="zts">Sign in first</b></div>
<div class="ztr ztd"><span>Simulate</span><select id="ztp"><option value="">Real GPS</option><option>At SOC</option><option>At Data Centre</option><option>At Head Office</option><option>Off-site</option></select></div>
<p class="axm">Network and location are verified by the server on every request. Simulators exist only while DEMO_MODE is on.</p>`;
const ctx=()=>({sim_net:$('#ztn').value,sim_site:$('#ztp').value,...(gps||{}),ts:gps?gps.ts:0});

/* real GPS fix (only after sign-in, only when not simulating) */
function fix(){if(!navigator.geolocation||$('#ztp').value)return;
 navigator.geolocation.getCurrentPosition(p=>{gps={lat:p.coords.latitude,lon:p.coords.longitude,acc:p.coords.accuracy,ts:p.timestamp}},()=>{gps=null},{enableHighAccuracy:true,maximumAge:5000,timeout:8000})}
setInterval(()=>{if(O&&O.user)fix()},5000);

/* login / logout */
function renderLogin(){
 $('#ztl').innerHTML=O.user?`<h3>🔐 Signed in</h3><p><b>${esc(O.user.name)}</b> <span class="tag">role: ${O.user.role}</span></p><button class="btn ghost" id="zlo">Sign out</button>`
 :`<h3>🔐 Sign in</h3><div class="ctl">${O.demo?`<select id="zlu">${(O.demo_users||[]).map(u=>`<option value="${u.name}">${u.name} (${u.role})</option>`).join('')}</select>`:'<input id="zlu" placeholder="username">'}<input id="zlp" type="password" placeholder="password"></div><div class="ctl"><button class="btn" id="zlg">Sign in</button></div><p class="axm" id="zle" style="color:var(--r)"></p>${O.demo?'<p class="axm">Demo password: <b>demo123</b></p>':''}`}
$('#ztl').onclick=async e=>{
 if(e.target.id=='zlg'){const r=await api('/api/secure/login',{user:$('#zlu').value,password:$('#zlp').value});if(r.error)$('#zle').textContent=r.error;else{fix();tick()}}
 if(e.target.id=='zlo'){await api('/api/secure/logout',{});closeV();tick()}};
$('#ztl').onkeydown=e=>{if(e.key=='Enter'&&e.target.id=='zlp')$('#zlg').click()};

/* overview poll: access matrix */
async function tick(){
 try{O=await api('/api/secure/overview',ctx())}catch(e){return}
 $('#znz').textContent=O.zone;$('#zip').textContent=O.ip;
 document.querySelectorAll('.ztd').forEach(r=>r.hidden=!O.demo);
 $('#zts').textContent=!O.user?'Sign in first':$('#ztp').value?'Simulated: '+$('#ztp').value:gps?`GPS fix ±${Math.round(gps.acc)} m`:'Waiting for location permission…';
 const who=O.user?O.user.name+'|'+O.user.role:'';
 if(who!==lastWho){lastWho=who;renderLogin();if(!O.user)closeV();aud()}
 const sig=JSON.stringify(O.streams);
 if(sig!==lastSig){lastSig=sig;
  $('#ztm').innerHTML=!O.user?'<p class="axm">Sign in to see the streams you can request.</p>':O.streams.map(s=>{const bad=s.decision.checks.filter(c=>!c.ok&&c.detail);
  return`<div class="zc ${s.decision.allowed?'ok':'no'}"><div class="zh"><span>${s.kind=='video'?'🎥':'📜'} ${esc(s.name)}</span><span class="tag lv-${s.level}">${s.level}</span></div>
  <div class="zp"><span class="tag">Role ≥ ${s.policy.role}</span>${s.policy.zones.map(z=>`<span class="tag">🌐 ${esc(z)}</span>`).join('')}${s.policy.sites.map(z=>`<span class="tag">📍 ${esc(z)}</span>`).join('')}</div>
  <div class="zk">${s.decision.checks.map(c=>`<span class="${c.ok?'y':'n'}">${c.ok?'✔':'✖'} ${c.name}</span>`).join('')}</div>
  ${bad.map(c=>`<small class="axm">✖ ${esc(c.detail)}</small>`).join('')}
  <button class="btn ${s.decision.allowed?'':'ghost'}" data-open="${s.id}">${s.decision.allowed?'▶ Open stream':'🔒 Request access'}</button></div>`}).join('')}
}
setInterval(tick,2500);tick();
$('#ztm').onclick=e=>{const b=e.target.closest('[data-open]');if(b)openStream(b.dataset.open)};

/* stream viewer with continuous re-authorisation */
function openStream(id){opened=id;seq=0;loglines=[];vmode='';const s=O.streams.find(x=>x.id==id);
 $('#ztv').hidden=false;
 $('#ztv').innerHTML=`<div class="zvh"><h3>${s.kind=='video'?'🎥':'📜'} ${esc(s.name)}</h3><span id="zvs" class="zvs">connecting…</span><button class="btn ghost" id="zvx">✕ Close</button></div><div id="zvb"></div>`;
 clearInterval(vt);vtick(1);vt=setInterval(()=>vtick(0),1500);setTimeout(aud,600);
 $('#ztv').scrollIntoView({behavior:'smooth',block:'center'})}
function closeV(){opened=null;clearInterval(vt);$('#ztv').hidden=true}
$('#ztv').onclick=e=>{if(e.target.id=='zvx')closeV()};
async function vtick(first){if(!opened)return;let o;
 try{o=await api('/api/secure/stream/'+opened,{...ctx(),since:seq,open:!!first})}catch(e){return}
 if(!opened)return;if(o.error){closeV();return}
 const s=O.streams.find(x=>x.id==opened),b=$('#zvb'),st=$('#zvs');if(!s||!b)return;
 if(!o.allowed){vmode='deny';loglines=[];seq=0;st.textContent='● BLOCKED';st.className='zvs bad';
  b.innerHTML=`<div class="zdeny"><div style="font-size:3rem">🔒</div><h4>ACCESS DENIED / REVOKED</h4>${o.checks.map(c=>`<div class="${c.ok?'y':'n'}">${c.ok?'✔':'✖'} ${c.name}${c.detail?' - '+esc(c.detail):''}</div>`).join('')}<p class="axm">The stream is blanked. It resumes automatically if the policy is satisfied again.</p></div>`;aud();return}
 st.textContent='● LIVE · watermarked to '+O.user.name;st.className='zvs ok';
 if(s.kind=='video'){if(vmode!='video'){vmode='video';b.innerHTML='<img id="zvi" alt="camera feed">'}
  $('#zvi').src='data:image/svg+xml;charset=utf-8,'+encodeURIComponent(o.frame)}
 else{if(vmode!='log'){vmode='log';b.innerHTML='<div class="ztlog" id="zvl"></div><p class="axm" id="zvm"></p>'}
  o.lines.forEach(l=>loglines.push(l.line));loglines=loglines.slice(-60);seq=o.seq;
  $('#zvl').innerHTML=loglines.map(l=>`<div class="${/^\S+\s+ERROR/.test(l)?'e':/^\S+\s+WARN/.test(l)?'w':''}">${esc(l)}</div>`).join('');$('#zvl').scrollTop=1e9;
  $('#zvm').textContent=O.user.role=='admin'?'Full-fidelity log.':'Field-level masking active for your role: account numbers'+(O.user.role=='senior'?'':', IPs and usernames')+' are redacted.'}}

/* audit trail + admin kill-switch */
async function aud(){
 if(!O||!O.user){$('#zta').hidden=true;return}
 let r;try{r=await api('/api/secure/audit',{})}catch(e){return}if(r.error)return;
 const prev=$('#zrv')?$('#zrv').value:'';
 $('#zta').hidden=false;
 $('#zta').innerHTML=`<h3>🧾 Access audit trail</h3>${r.can_revoke?`<div class="ctl"><select id="zrv">${r.users.map(u=>`<option ${u==prev?'selected':''}>${u}</option>`).join('')}</select><button class="btn ghost" id="zrb">⛔ Force sign-out</button></div>`:''}
 <div class="tw"><table><thead><tr><th>Time</th><th>User</th><th>Stream</th><th>Decision</th><th>Network</th><th>Location</th><th>Failed checks</th></tr></thead><tbody>${r.rows.map(x=>`<tr><td>${new Date(x.ts*1000).toLocaleTimeString()}</td><td>${esc(x.user)} <small>${x.role}</small></td><td>${esc(x.stream)}</td><td class="${x.allowed?'y':'n'}">${x.allowed?'✔ Allowed':'✖ Denied'}</td><td>${esc(x.zone)}<small>${esc(x.ip)}</small></td><td>${esc(x.loc)}</td><td>${esc(x.reasons)}</td></tr>`).join('')}</tbody></table></div>`}
$('#zta').onclick=async e=>{if(e.target.id=='zrb'){await api('/api/secure/revoke',{user:$('#zrv').value});aud()}};
setInterval(aud,6000);
})();