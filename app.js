(function () {
  "use strict";

  // ---------- конфиг ----------
  // Ответы хранятся только как SHA-256(SALT:id:ответ).
  // Новый хэш: node scripts/hash.mjs <id> "flag{...}"
  // SALT здесь и в scripts/hash.mjs должен совпадать.
  var SALT = "glug-path-v1";
  var FLAGS = [
    { id: 1, title: "Флаг 1", hash: "7d674223381caeb20c5f5d433050896be16974910d21d81b32cb3c35699f3e3e" },
    { id: 2, title: "Флаг 2", hash: "c837509823296897382c2eefe89732bda01bc0add9c1c3ad8ddb666229f0e690" },
    { id: 3, title: "Флаг 3", hash: "afc803e6a07cb2c863937634b96bfe98e39df81adc0d07438232d153fb724c27" }
  ];
  var STORAGE_KEY = "flag-path-progress-v2:" + SALT;

  // ---------- SHA-256 (чистый JS, работает и по http, и с file://) ----------
  var sha256 = (function () {
    var K = [], H = [];
    var frac = function (x) { return ((x - Math.floor(x)) * 0x100000000) | 0; };
    for (var n = 2, found = 0; found < 64; n++) {
      var prime = true;
      for (var d = 2; d * d <= n; d++) if (n % d === 0) { prime = false; break; }
      if (!prime) continue;
      if (found < 8) H[found] = frac(Math.pow(n, 1 / 2));
      K[found++] = frac(Math.pow(n, 1 / 3));
    }
    var ror = function (x, r) { return (x >>> r) | (x << (32 - r)); };

    return function (str) {
      var bytes = new TextEncoder().encode(str);
      var len = bytes.length;
      var total = Math.ceil((len + 9) / 64) * 64;
      var msg = new Uint8Array(total);
      msg.set(bytes);
      msg[len] = 0x80;
      var dv = new DataView(msg.buffer);
      var bits = len * 8;
      dv.setUint32(total - 8, Math.floor(bits / 0x100000000));
      dv.setUint32(total - 4, bits >>> 0);

      var h = H.slice();
      var w = new Int32Array(64);
      for (var off = 0; off < total; off += 64) {
        for (var i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4);
        for (i = 16; i < 64; i++) {
          var x = w[i - 15], y = w[i - 2];
          var s0 = ror(x, 7) ^ ror(x, 18) ^ (x >>> 3);
          var s1 = ror(y, 17) ^ ror(y, 19) ^ (y >>> 10);
          w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
        }
        var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (i = 0; i < 64; i++) {
          var S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
          var ch = (e & f) ^ (~e & g);
          var t1 = (hh + S1 + ch + K[i] + w[i]) | 0;
          var S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
          var maj = (a & b) ^ (a & c) ^ (b & c);
          var t2 = (S0 + maj) | 0;
          hh = g; g = f; f = e; e = (d + t1) | 0;
          d = c; c = b; b = a; a = (t1 + t2) | 0;
        }
        h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
        h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
      }
      return h.map(function (v) { return ("0000000" + (v >>> 0).toString(16)).slice(-8); }).join("");
    };
  })();
  window.__sha256 = sha256; // для самопроверки в консоли

  // ---------- состояние ----------
  // { id: "flag{...}" } — введённые верные ответы, чтобы показывать их после перезагрузки
  var solved = {};
  try {
    var saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
    FLAGS.forEach(function (fl) {
      if (typeof saved[fl.id] === "string") solved[fl.id] = saved[fl.id];
    });
  } catch (err) { /* без localStorage просто не запоминаем */ }

  function save() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(solved)); } catch (err) {}
  }

  function isSolved(id) {
    return Object.prototype.hasOwnProperty.call(solved, id);
  }

  function solvedCount() {
    return FLAGS.filter(function (fl) { return isSolved(fl.id); }).length;
  }

  // ---------- разметка ----------
  var trail = document.getElementById("trail");
  var trailSvg = document.getElementById("trail-svg");
  var tpl = document.getElementById("station-tpl");
  var progressEl = document.getElementById("progress");
  var victoryEl = document.getElementById("victory");
  var stations = {};

  FLAGS.forEach(function (fl) {
    var node = tpl.content.firstElementChild.cloneNode(true);
    var input = node.querySelector("input");
    var label = node.querySelector("label");
    var inputId = "flag-input-" + fl.id;
    input.id = inputId;
    label.htmlFor = inputId;
    label.textContent = "Ответ для: " + fl.title;
    node.querySelector(".station-title").textContent = fl.title;
    node.dataset.id = fl.id;

    var clipId = "flag-clip-" + fl.id;
    node.querySelector(".flag-clip").id = clipId;
    node.querySelector(".fabric-green").setAttribute("clip-path", "url(#" + clipId + ")");

    node.querySelector("form").addEventListener("submit", function (ev) {
      ev.preventDefault();
      check(fl, node, input);
    });
    input.addEventListener("input", function () { node.classList.remove("wrong"); });

    trail.appendChild(node);
    stations[fl.id] = node;
    if (isSolved(fl.id)) {
      markSolved(node, solved[fl.id]);
      setFill(node, 1, 0);
    }
  });

  function markSolved(node, answer) {
    node.classList.remove("wrong");
    node.classList.add("solved");
    var input = node.querySelector("input");
    var btn = node.querySelector("button");
    input.value = answer;
    input.readOnly = true;
    btn.disabled = true;
    btn.textContent = "Взят";
    node.querySelector(".status").textContent = "Флаг захвачен!";
  }

  // ---------- заливка флага зелёным ----------
  // Работает и при prefers-reduced-motion: это плавное проявление цвета, без тряски.
  // Зелёная копия полотнища открывается клипом с волнистым краем, который едет от древка к хвосту.
  function setFill(node, t, phase) {
    var shape = node.querySelector(".flag-clip-shape");
    if (t >= 1) { shape.setAttribute("d", "M-20,-20H240V160H-20Z"); return; }
    var edge = -30 + t * 260;                 // полотнище: x 5..196
    var amp = 4 + 9 * Math.sin(Math.PI * t);  // волна сильнее в середине
    var d = "M-20,-20";
    for (var y = -20; y <= 160; y += 6) {
      d += "L" + (edge + amp * Math.sin(y / 13 + phase)).toFixed(1) + "," + y;
    }
    shape.setAttribute("d", d + "L-20,160Z");
  }

  function animateFill(node, duration, done) {
    node.classList.remove("capturing");
    void node.offsetWidth;
    node.classList.add("capturing");
    var t0 = performance.now();
    (function frame(now) {
      var k = Math.min(1, (now - t0) / duration);
      var eased = k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2;
      setFill(node, eased, k * 12);
      if (k < 1) requestAnimationFrame(frame);
      else { node.classList.remove("capturing"); done(); }
    })(t0);
  }

  function check(fl, node, input) {
    var value = input.value.trim();
    var status = node.querySelector(".status");
    if (!value) {
      status.textContent = "Введи flag{...}";
      return;
    }
    if (sha256(SALT + ":" + fl.id + ":" + value) === fl.hash) {
      solved[fl.id] = value;
      save();
      markSolved(node, value);
      updateCounter();

      var r = node.querySelector(".flag").getBoundingClientRect();
      animateFill(node, 1100, function () {
        confetti.burst(r.left + r.width * 0.45, r.top + r.height * 0.25, 60, 1);
        var roadTime = drawTrail(fl.id);
        if (solvedCount() === FLAGS.length) setTimeout(confetti.celebrate, roadTime + 150);
      });
    } else {
      node.classList.remove("wrong");
      void node.offsetWidth; // перезапуск анимации тряски
      node.classList.add("wrong");
      status.textContent = "Неверно. Попробуй ещё.";
      input.select();
    }
  }

  function updateCounter() {
    var count = solvedCount();
    progressEl.textContent = count + " / " + FLAGS.length;
    victoryEl.hidden = count !== FLAGS.length;
  }

  // ---------- дороги между флагами ----------
  // Дорога открывается, когда взяты оба флага на её концах.
  var mobileMq = window.matchMedia("(max-width: 760px)");
  var ROAD_MS = 1200;

  // capturedId — только что взятый флаг: от него новые дороги «прорисовываются» к соседям.
  // Возвращает длительность анимации (0, если ничего не открылось).
  function drawTrail(capturedId) {
    var box = trail.getBoundingClientRect();
    var pts = FLAGS.map(function (fl) {
      var r = stations[fl.id].querySelector(".base").getBoundingClientRect();
      return { x: r.left + r.width / 2 - box.left, y: r.top + r.height / 2 - box.top };
    });

    var svgNs = "http://www.w3.org/2000/svg";
    var animated = 0;
    trailSvg.textContent = "";
    for (var i = 0; i < pts.length - 1; i++) {
      var p = pts[i], q = pts[i + 1], d;
      if (mobileMq.matches) {
        // в колонку: обходим форму слева, чтобы линия не перечёркивала поля
        var lx = 6, rad = 18;
        d = "M" + p.x + "," + p.y +
          " H" + (lx + rad) + " Q" + lx + "," + p.y + " " + lx + "," + (p.y + rad) +
          " V" + (q.y - rad) + " Q" + lx + "," + q.y + " " + (lx + rad) + "," + q.y +
          " H" + q.x;
      } else {
        // по земле под флагом, поворот только в промежутке между станциями
        var g1 = stations[FLAGS[i].id].getBoundingClientRect().right - box.left;
        var g2 = stations[FLAGS[i + 1].id].getBoundingClientRect().left - box.left;
        var gm = (g1 + g2) / 2;
        d = "M" + p.x + "," + p.y + " H" + g1 +
          " C" + gm + "," + p.y + " " + gm + "," + q.y + " " + g2 + "," + q.y +
          " H" + q.x;
      }

      var road = document.createElementNS(svgNs, "path");
      road.setAttribute("d", d);
      road.setAttribute("class", "road");
      trailSvg.appendChild(road);

      var a = FLAGS[i].id, b = FLAGS[i + 1].id;
      if (!isSolved(a) || !isSolved(b)) continue;

      var glow = document.createElementNS(svgNs, "path");
      glow.setAttribute("d", d);
      glow.setAttribute("class", "road-glow");
      var open = document.createElementNS(svgNs, "path");
      open.setAttribute("d", d);
      open.setAttribute("class", "road-open");
      trailSvg.appendChild(glow);
      trailSvg.appendChild(open);

      var isNew = capturedId === a || capturedId === b;
      if (isNew && open.animate) {
        var len = open.getTotalLength();
        // от взятого флага к соседу: с начала пути или с конца
        var from = capturedId === a ? len : -len;
        var target = stations[capturedId === a ? b : a].querySelector(".base");
        open.style.strokeDasharray = len + " " + len;
        open.animate(
          [{ strokeDashoffset: from }, { strokeDashoffset: 0 }],
          { duration: ROAD_MS, easing: "cubic-bezier(.65,0,.35,1)", fill: "both" }
        );
        glow.animate(
          [{ opacity: 0 }, { opacity: 0.35, offset: 0.8 }, { opacity: 0 }],
          { duration: ROAD_MS + 400, easing: "ease-out" }
        );
        setTimeout(lightUp.bind(null, target), ROAD_MS - 80);
        animated = ROAD_MS;
      }
    }
    return animated;
  }

  function lightUp(base) {
    base.classList.remove("lit");
    void base.offsetWidth;
    base.classList.add("lit");
  }

  function redraw() { drawTrail(null); }

  window.addEventListener("resize", redraw);
  if (window.ResizeObserver) new ResizeObserver(redraw).observe(trail);

  document.getElementById("reset").addEventListener("click", function () {
    try { localStorage.removeItem(STORAGE_KEY); } catch (err) {}
    location.reload();
  });

  // ---------- конфетти ----------
  var confetti = (function () {
    var canvas = document.getElementById("confetti");
    var ctx = canvas.getContext("2d");
    var colors = ["#ec5a3c", "#3db866", "#f7c548", "#2f80ed", "#ffffff", "#9b51e0"];
    var parts = [];
    var running = false;
    var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    function resize() {
      var dpr = window.devicePixelRatio || 1;
      canvas.width = innerWidth * dpr;
      canvas.height = innerHeight * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    resize();
    window.addEventListener("resize", resize);

    // angle — направление вылета (рад), spread — разброс, power — скорость
    function spawn(x, y, n, angle, spread, power) {
      if (reduce) n = Math.ceil(n / 4);
      for (var i = 0; i < n; i++) {
        var a = angle + (Math.random() - 0.5) * spread;
        var v = power * (0.5 + Math.random() * 0.7);
        parts.push({
          x: x, y: y,
          vx: Math.cos(a) * v, vy: Math.sin(a) * v,
          w: 6 + Math.random() * 6, h: 4 + Math.random() * 4,
          rot: Math.random() * Math.PI, vr: (Math.random() - 0.5) * 0.3,
          tilt: Math.random() * Math.PI * 2,
          color: colors[(Math.random() * colors.length) | 0],
          life: 0, max: 110 + Math.random() * 70
        });
      }
      if (!running) { running = true; requestAnimationFrame(tick); }
    }

    function tick() {
      ctx.clearRect(0, 0, innerWidth, innerHeight);
      for (var i = parts.length - 1; i >= 0; i--) {
        var p = parts[i];
        p.vy += 0.18;
        p.vx *= 0.985; p.vy *= 0.985;
        p.x += p.vx; p.y += p.vy;
        p.rot += p.vr; p.tilt += 0.12;
        p.life++;
        if (p.life > p.max || p.y > innerHeight + 40) { parts.splice(i, 1); continue; }
        ctx.save();
        ctx.globalAlpha = Math.min(1, (p.max - p.life) / 30);
        ctx.translate(p.x, p.y);
        ctx.rotate(p.rot);
        ctx.scale(1, Math.cos(p.tilt));
        ctx.fillStyle = p.color;
        ctx.fillRect(-p.w / 2, -p.h / 2, p.w, p.h);
        ctx.restore();
      }
      if (parts.length) requestAnimationFrame(tick);
      else { running = false; ctx.clearRect(0, 0, innerWidth, innerHeight); }
    }

    return {
      // небольшой залп из флага
      burst: function (x, y, n, scale) {
        spawn(x, y, n * scale, -Math.PI / 2, Math.PI * 1.1, 9 * scale);
      },
      // финал: пушки из нижних углов + дождь сверху
      celebrate: function () {
        var W = innerWidth, Hh = innerHeight;
        var waves = 4;
        for (var k = 0; k < waves; k++) {
          setTimeout(function () {
            spawn(0, Hh, 70, -Math.PI / 3, 0.7, 22);
            spawn(W, Hh, 70, -Math.PI * 2 / 3, 0.7, 22);
            for (var j = 0; j < 40; j++) {
              spawn(Math.random() * W, -10, 1, Math.PI / 2, 0.6, 3);
            }
          }, k * 450);
        }
      }
    };
  })();

  updateCounter();
  redraw();
})();
