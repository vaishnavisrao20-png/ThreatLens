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