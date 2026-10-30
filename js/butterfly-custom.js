(function() {
  'use strict';

  const reducedMotion = window.matchMedia
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  let canvas = null;
  let ctx = null;
  let nodes = [];
  let width = 0;
  let height = 0;
  let raf = 0;
  let revealObserver = null;
  let glow = null;
  let glowRaf = 0;
  let resizeTimer = 0;
  const pointer = { x: 0, y: 0, tx: 0, ty: 0 };
  const mouse = { x: -9999, y: -9999 };

  function themeColors() {
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    return dark
      ? { line: '78,216,199', gold: '224,187,78', node: '78,216,199' }
      : { line: '43,179,163', gold: '201,162,39', node: '43,179,163' };
  }

  /* ---------- 背景粒子 ---------- */
  function resizeParticles() {
    if (!canvas || !ctx) return;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    const count = Math.min(92, Math.max(26, Math.floor(width * height / 22000)));
    nodes = Array.from({ length: count }, function() {
      return {
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.22,
        vy: (Math.random() - 0.5) * 0.22,
        r: Math.random() * 1.5 + 0.55,
        gold: Math.random() < 0.18
      };
    });
  }

  function drawParticles() {
    if (!ctx) return;
    ctx.clearRect(0, 0, width, height);
    const colors = themeColors();

    for (let i = 0; i < nodes.length; i += 1) {
      const node = nodes[i];

      if (!reducedMotion) {
        node.x += node.vx;
        node.y += node.vy;
        if (node.x < -20 || node.x > width + 20) node.vx *= -1;
        if (node.y < -20 || node.y > height + 20) node.vy *= -1;

        const dx = node.x - mouse.x;
        const dy = node.y - mouse.y;
        const d2 = dx * dx + dy * dy;
        if (d2 < 18000 && d2 > 0.01) {
          const d = Math.sqrt(d2);
          node.x += dx / d * 0.35;
          node.y += dy / d * 0.35;
        }
      }

      const color = node.gold ? colors.gold : colors.node;
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(' + color + ',' + (node.gold ? 0.52 : 0.4) + ')';
      ctx.fill();

      for (let j = i + 1; j < nodes.length; j += 1) {
        const other = nodes[j];
        const dx = node.x - other.x;
        const dy = node.y - other.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 110) {
          ctx.beginPath();
          ctx.moveTo(node.x, node.y);
          ctx.lineTo(other.x, other.y);
          ctx.strokeStyle = 'rgba(' + colors.line + ',' + (1 - dist / 110) * 0.14 + ')';
          ctx.lineWidth = 0.7;
          ctx.stroke();
        }
      }
    }

    if (mouse.x > 0) {
      for (let i = 0; i < nodes.length; i += 1) {
        const node = nodes[i];
        const dx = node.x - mouse.x;
        const dy = node.y - mouse.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 160) {
          ctx.beginPath();
          ctx.moveTo(node.x, node.y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.strokeStyle = 'rgba(' + colors.line + ',' + (1 - dist / 160) * 0.22 + ')';
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }
    }

    if (!reducedMotion) raf = requestAnimationFrame(drawParticles);
  }

  function startParticles() {
    if (reducedMotion) return;
    if (!canvas) {
      canvas = document.createElement('canvas');
      canvas.id = 'q-particles';
      canvas.setAttribute('aria-hidden', 'true');
      document.body.appendChild(canvas);
      ctx = canvas.getContext('2d');
    }
    if (!ctx) return;
    resizeParticles();
    cancelAnimationFrame(raf);
    raf = 0;
    drawParticles();
  }

  /* ---------- 鼠标光晕 ---------- */
  function startGlow() {
    if (reducedMotion) return;
    if (!glow) {
      glow = document.createElement('div');
      glow.id = 'q-cursor-glow';
      glow.setAttribute('aria-hidden', 'true');
      document.body.appendChild(glow);
      pointer.x = pointer.tx = window.innerWidth / 2;
      pointer.y = pointer.ty = window.innerHeight / 2;
    }

    function tick() {
      pointer.x += (pointer.tx - pointer.x) * 0.12;
      pointer.y += (pointer.ty - pointer.y) * 0.12;
      glow.style.transform = 'translate3d(' + pointer.x.toFixed(1) + 'px,' + pointer.y.toFixed(1) + 'px,0)';
      glowRaf = requestAnimationFrame(tick);
    }

    if (!glowRaf) tick();
  }

  /* ---------- 滚动进场 ---------- */
  function startReveal() {
    if (revealObserver) revealObserver.disconnect();

    // 只对首页与文首系列导航做进场动画，避免跳转目录时正文元素被跳过而保持透明
    const elements = document.querySelectorAll(
      '.home-hero, .home-section-head, .home-post-card, .series-nav'
    );

    if (reducedMotion || !('IntersectionObserver' in window)) {
      elements.forEach(function(el) { el.classList.add('q-reveal', 'is-visible'); });
      return;
    }

    revealObserver = new IntersectionObserver(function(entries) {
      entries.forEach(function(entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          revealObserver.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -6% 0px', threshold: 0.05 });

    elements.forEach(function(el) {
      if (!el.classList.contains('q-reveal')) el.classList.add('q-reveal');
      if (!el.classList.contains('is-visible')) revealObserver.observe(el);
    });
  }

  /* ---------- 卡片倾斜 ---------- */
  function startTilt() {
    if (reducedMotion) return;

    document.querySelectorAll('.q-tilt').forEach(function(card) {
      if (card.dataset.qTilt) return;
      card.dataset.qTilt = '1';

      card.addEventListener('mousemove', function(event) {
        const rect = card.getBoundingClientRect();
        const x = (event.clientX - rect.left) / rect.width - 0.5;
        const y = (event.clientY - rect.top) / rect.height - 0.5;
        card.style.setProperty('--tilt-y', (x * 5).toFixed(2) + 'deg');
        card.style.setProperty('--tilt-x', (-y * 5).toFixed(2) + 'deg');
      });

      card.addEventListener('mouseleave', function() {
        card.style.setProperty('--tilt-y', '0deg');
        card.style.setProperty('--tilt-x', '0deg');
      });
    });
  }

  /* ---------- Hero 视差 ---------- */
  function startHeroParallax() {
    if (reducedMotion) return;

    document.querySelectorAll('.home-hero').forEach(function(hero) {
      if (hero.dataset.qParallax) return;
      hero.dataset.qParallax = '1';

      hero.addEventListener('mousemove', function(event) {
        const rect = hero.getBoundingClientRect();
        const mx = ((event.clientX - rect.left) / rect.width - 0.5) * 2;
        const my = ((event.clientY - rect.top) / rect.height - 0.5) * 2;
        hero.style.setProperty('--q-mx', mx.toFixed(3));
        hero.style.setProperty('--q-my', my.toFixed(3));
      });

      hero.addEventListener('mouseleave', function() {
        hero.style.setProperty('--q-mx', '0');
        hero.style.setProperty('--q-my', '0');
      });
    });
  }

  /* ---------- 导航滚动状态 ---------- */
  function startNavState() {
    if (!window.__qNavUpdate) {
      window.__qNavUpdate = function() {
        const header = document.getElementById('page-header');
        if (header) header.classList.toggle('q-scrolled', window.scrollY > 24);
      };
    }

    window.__qNavUpdate();

    if (!window.__qNavBound) {
      window.addEventListener('scroll', window.__qNavUpdate, { passive: true });
      window.__qNavBound = true;
    }
  }

  function updateHomeClass() {
    document.body.classList.toggle('home-custom', !!document.querySelector('.home-shell'));
  }

  function initAll() {
    updateHomeClass();
    startParticles();
    startGlow();
    startReveal();
    startTilt();
    startHeroParallax();
    startNavState();
  }

  function bindGlobalEvents() {
    if (window.__qGlobalBound) return;
    window.__qGlobalBound = true;

    window.addEventListener('mousemove', function(event) {
      mouse.x = event.clientX;
      mouse.y = event.clientY;
      pointer.tx = event.clientX;
      pointer.ty = event.clientY;
      document.body.classList.add('q-pointer');
    }, { passive: true });

    document.addEventListener('mouseleave', function() {
      mouse.x = -9999;
      mouse.y = -9999;
      document.body.classList.remove('q-pointer');
    });

    window.addEventListener('resize', function() {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function() {
        if (!canvas) return;
        resizeParticles();
        if (reducedMotion) drawParticles();
      }, 180);
    });

    document.addEventListener('visibilitychange', function() {
      if (document.hidden) {
        cancelAnimationFrame(raf);
        raf = 0;
      } else if (!raf && canvas && !reducedMotion) {
        drawParticles();
      }
    });
  }

  function boot() {
    bindGlobalEvents();
    initAll();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  document.addEventListener('pjax:complete', initAll);
})();
