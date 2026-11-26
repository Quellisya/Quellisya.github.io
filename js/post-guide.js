(function() {
  'use strict';

  var reduceMotion = window.matchMedia
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var ticking = false;

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
  }

  function normalize(text) {
    return String(text || '').replace(/\s+/g, '').trim();
  }

  function isConnected(element) {
    return document.documentElement.contains(element);
  }

  // data-target 是构建时解析出的真实标题 id；
  // 找不到时退回按标题文字匹配，避免改标题后知识点失效。
  function findTarget(link) {
    var id = link.getAttribute('data-target');
    if (id) {
      var element = document.getElementById(id);
      if (element) return element;
      try {
        element = document.getElementById(decodeURIComponent(id));
        if (element) return element;
      } catch (error) {
        /* 非法编码，忽略 */
      }
    }

    var heading = normalize(link.getAttribute('data-heading'));
    if (!heading) return null;

    var nodes = document.querySelectorAll(
      '#article-container h1, #article-container h2, ' +
      '#article-container h3, #article-container h4'
    );
    for (var i = 0; i < nodes.length; i += 1) {
      if (normalize(nodes[i].textContent) === heading) return nodes[i];
    }
    return null;
  }

  function setActive(guide, index) {
    if (guide.__qActive === index) return;
    guide.__qActive = index;

    (guide.__qButtons || []).forEach(function(link, i) {
      var active = i === index;
      link.classList.toggle('is-active', active);
      if (active) {
        link.setAttribute('aria-current', 'true');
      } else {
        link.removeAttribute('aria-current');
      }
    });
  }

  function updateGuide(guide) {
    var order = guide.__qOrder || [];
    if (!order.length) return;

    // 按正文顺序找最后一个已经越过分隔线的章节，再点亮对应知识点
    var line = window.innerHeight * 0.38;
    var current = order[0];
    for (var i = 0; i < order.length; i += 1) {
      if (order[i].target.getBoundingClientRect().top <= line) current = order[i];
    }
    setActive(guide, current.link.__qIndex);
  }

  function updateAll() {
    document.querySelectorAll('[data-q-guide]').forEach(updateGuide);
  }

  function requestUpdate() {
    if (ticking) return;
    ticking = true;
    window.requestAnimationFrame(function() {
      ticking = false;
      updateAll();
    });
  }

  function scrollToTarget(target) {
    var top = target.getBoundingClientRect().top + window.pageYOffset - 96;

    if (typeof window.scrollTo === 'function') {
      try {
        window.scrollTo({ top: top, behavior: reduceMotion ? 'auto' : 'smooth' });
      } catch (error) {
        window.scrollTo(0, top);
      }
    } else {
      window.scrollTo(0, top);
    }

    try {
      history.replaceState(null, '', '#' + target.id);
    } catch (error) {
      /* file:// 等环境下忽略 */
    }

    target.classList.remove('q-guide-target');
    // 强制重排，让连点同一个章节也能重新播放高亮
    void target.offsetWidth;
    target.classList.add('q-guide-target');
    window.setTimeout(function() {
      target.classList.remove('q-guide-target');
    }, 1500);
  }

  /* ------------------------------------------------------------------
     星域：缩放、拖拽、漂浮、星座连线
     ------------------------------------------------------------------ */
  function setupStarfield(guide) {
    var viewport = guide.querySelector('[data-q-viewport]');
    var canvas = guide.querySelector('[data-q-canvas]');
    var lineLayer = guide.querySelector('[data-q-lines]');
    if (!viewport || !canvas) return;

    var view = { x: 0, y: 0, s: 1 };
    var glideTimer = 0;

    guide.__qView = view;
    guide.__qInteracted = false;
    guide.__qDragMoved = false;

    var bubbles = Array.prototype.slice.call(
      canvas.querySelectorAll('.q-guide__bubble')
    );

    var points = bubbles.map(function(bubble, index) {
      var x = parseFloat(bubble.getAttribute('data-x'));
      var y = parseFloat(bubble.getAttribute('data-y'));
      var mine = bubble.classList.contains('is-mine');
      var size = bubble.offsetWidth || 60;

      bubble.__q = {
        baseX: Number.isFinite(x) ? x : 500,
        baseY: Number.isFinite(y) ? y : 300,
        radius: size / 2,
        mine: mine,
        dx: 0,
        dy: 0,
        ampX: mine ? 6 : 12 + (index % 5) * 3,
        ampY: mine ? 4 : 8 + (index % 4) * 3,
        speed: (mine ? 0.22 : 0.16) + (index % 7) * 0.018,
        phase: index * 1.7
      };

      return bubble;
    });

    var minePoints = points.filter(function(point) { return point.__q.mine; });

    function boxOf(list) {
      var minX = Infinity;
      var maxX = -Infinity;
      var minY = Infinity;
      var maxY = -Infinity;

      list.forEach(function(point) {
        var data = point.__q;
        minX = Math.min(minX, data.baseX - data.radius);
        maxX = Math.max(maxX, data.baseX + data.radius);
        minY = Math.min(minY, data.baseY - data.radius);
        maxY = Math.max(maxY, data.baseY + data.radius);
      });

      if (!Number.isFinite(minX)) {
        return { minX: 0, maxX: 1000, minY: 0, maxY: 600 };
      }

      return { minX: minX, maxX: maxX, minY: minY, maxY: maxY };
    }

    function apply(animate) {
      if (animate) {
        canvas.classList.add('is-gliding');
        void canvas.offsetWidth;
      } else {
        canvas.classList.remove('is-gliding');
      }

      canvas.style.transform =
        'translate3d(' + view.x.toFixed(2) + 'px,' +
        view.y.toFixed(2) + 'px,0) scale(' + view.s.toFixed(4) + ')';

      if (animate) {
        window.clearTimeout(glideTimer);
        glideTimer = window.setTimeout(function() {
          canvas.classList.remove('is-gliding');
        }, 1000);
      }
    }

    function fitToBox(box, animate) {
      var rect = viewport.getBoundingClientRect();
      if (!rect.width || !rect.height) return;

      var padding = 56;
      var width = Math.max(1, box.maxX - box.minX) + padding * 2;
      var height = Math.max(1, box.maxY - box.minY) + padding * 2;
      var scale = clamp(Math.min(rect.width / width, rect.height / height), 0.45, 1.6);

      view.s = scale;
      view.x = rect.width / 2 - scale * (box.minX + box.maxX) / 2;
      view.y = rect.height / 2 - scale * (box.minY + box.maxY) / 2;
      apply(animate);
    }

    function fitMine(animate) {
      fitToBox(boxOf(minePoints.length ? minePoints : points), animate);
    }

    function zoomAtCenter(factor) {
      var rect = viewport.getBoundingClientRect();
      if (!rect.width || !rect.height) return;

      var cx = rect.width / 2;
      var cy = rect.height / 2;
      var worldX = (cx - view.x) / view.s;
      var worldY = (cy - view.y) / view.s;
      var scale = clamp(view.s * factor, 0.45, 2.4);

      view.s = scale;
      view.x = cx - scale * worldX;
      view.y = cy - scale * worldY;
      apply(false);
    }

    // 只把本文的知识点连成一条星座；用最近邻排序，避免太多交叉
    var chain = [];
    var remaining = minePoints.slice();

    if (remaining.length > 1) {
      chain.push(remaining.shift());
      while (remaining.length) {
        var last = chain[chain.length - 1].__q;
        var bestIndex = 0;
        var bestDistance = Infinity;

        remaining.forEach(function(point, index) {
          var dx = point.__q.baseX - last.baseX;
          var dy = point.__q.baseY - last.baseY;
          var distance = dx * dx + dy * dy;
          if (distance < bestDistance) {
            bestDistance = distance;
            bestIndex = index;
          }
        });

        chain.push(remaining.splice(bestIndex, 1)[0]);
      }
    } else if (remaining.length === 1) {
      chain.push(remaining[0]);
    }

    var lineItems = [];
    if (lineLayer) {
      for (var i = 1; i < chain.length; i += 1) {
        var line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('class', 'q-guide__line');
        lineLayer.appendChild(line);
        lineItems.push({ el: line, a: chain[i - 1].__q, b: chain[i].__q });
      }
    }

    function updateLines() {
      lineItems.forEach(function(item) {
        item.el.setAttribute('x1', (item.a.baseX + item.a.dx).toFixed(2));
        item.el.setAttribute('y1', (item.a.baseY + item.a.dy).toFixed(2));
        item.el.setAttribute('x2', (item.b.baseX + item.b.dx).toFixed(2));
        item.el.setAttribute('y2', (item.b.baseY + item.b.dy).toFixed(2));
      });
    }

    function tick(now) {
      if (!isConnected(guide)) {
        window.cancelAnimationFrame(guide.__qRaf);
        return;
      }

      var time = now / 1000;

      points.forEach(function(point) {
        var data = point.__q;
        data.dx = Math.sin(time * data.speed + data.phase) * data.ampX;
        data.dy = Math.cos(time * data.speed * 1.27 + data.phase * 1.37) * data.ampY;
        point.style.setProperty('--dx', data.dx.toFixed(2) + 'px');
        point.style.setProperty('--dy', data.dy.toFixed(2) + 'px');
      });

      updateLines();
      guide.__qRaf = window.requestAnimationFrame(tick);
    }

    // 先展示整张星图，再自动缩放到本文星座
    fitToBox(boxOf(points), false);
    updateLines();
    canvas.classList.add('is-ready');

    if (reduceMotion) {
      fitMine(false);
      updateLines();
    } else {
      window.requestAnimationFrame(function() {
        window.setTimeout(function() {
          if (!isConnected(guide) || guide.__qInteracted) return;
          fitMine(true);
        }, 260);
      });
      guide.__qRaf = window.requestAnimationFrame(tick);
    }

    // 拖拽平移
    var drag = null;

    viewport.addEventListener('pointerdown', function(event) {
      if (event.target.closest('.q-guide__controls')) return;
      if (event.pointerType === 'mouse' && event.button !== 0) return;

      drag = {
        id: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        tx: view.x,
        ty: view.y,
        moved: false
      };
      guide.__qDragMoved = false;
    });

    viewport.addEventListener('pointermove', function(event) {
      if (!drag || drag.id !== event.pointerId) return;

      var dx = event.clientX - drag.startX;
      var dy = event.clientY - drag.startY;

      if (!drag.moved && Math.abs(dx) + Math.abs(dy) > 8) {
        drag.moved = true;
        guide.__qDragMoved = true;
        guide.__qInteracted = true;
        viewport.classList.add('is-dragging');

        // 只有确认是拖拽后才捕获指针；
        // 普通点击不捕获，click 才会正常落到小球链接上。
        try {
          viewport.setPointerCapture(event.pointerId);
        } catch (error) {
          /* 某些浏览器不支持，忽略 */
        }
      }

      if (!drag.moved) return;

      view.x = drag.tx + dx;
      view.y = drag.ty + dy;
      apply(false);
    });

    function endDrag(event) {
      if (!drag || drag.id !== event.pointerId) return;
      drag = null;
      viewport.classList.remove('is-dragging');

      if (guide.__qDragMoved) {
        window.setTimeout(function() {
          guide.__qDragMoved = false;
        }, 150);
      }
    }

    viewport.addEventListener('pointerup', endDrag);
    viewport.addEventListener('pointercancel', endDrag);

    // 拖拽后不要误触链接 / 章节跳转
    viewport.addEventListener('click', function(event) {
      if (!guide.__qDragMoved) return;
      event.preventDefault();
      event.stopPropagation();
    }, true);

    // 缩放按钮
    viewport.querySelectorAll('[data-q-zoom]').forEach(function(button) {
      button.addEventListener('click', function(event) {
        event.preventDefault();
        event.stopPropagation();
        guide.__qInteracted = true;

        var action = button.getAttribute('data-q-zoom');
        if (action === 'fit') {
          fitMine(true);
          return;
        }

        zoomAtCenter(action === 'in' ? 1.22 : 1 / 1.22);
      });
    });

    // 窗口尺寸变化时，如果用户还没操作过，重新聚焦到本文星座
    var resizeTimer = 0;
    window.addEventListener('resize', function() {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(function() {
        if (!isConnected(guide) || guide.__qInteracted) return;
        fitMine(false);
      }, 220);
    });

    guide.__qFit = function() {
      guide.__qInteracted = true;
      fitMine(true);
    };
  }

  function bindGuide(guide) {
    if (guide.__qBound) return;
    guide.__qBound = true;

    // 只有本文涉及的知识点参与滚动点亮；其他知识点是跨文章链接
    var links = Array.prototype.slice.call(
      guide.querySelectorAll('.q-guide__bubble.is-mine')
    );

    var entries = links.map(function(link, index) {
      link.__qIndex = index;
      return { link: link, target: findTarget(link) };
    });

    guide.__qButtons = links;
    guide.__qOrder = entries
      .filter(function(entry) { return !!entry.target; })
      .sort(function(a, b) {
        var position = a.target.compareDocumentPosition(b.target);
        if (position & Node.DOCUMENT_POSITION_FOLLOWING) return -1;
        if (position & Node.DOCUMENT_POSITION_PRECEDING) return 1;
        return 0;
      });

    entries.forEach(function(entry) {
      var link = entry.link;
      var target = entry.target;

      link.addEventListener('click', function(event) {
        if (guide.__qDragMoved) {
          event.preventDefault();
          return;
        }
        if (!target) {
          // 没有解析到章节时不要跳到 #，留在原地
          event.preventDefault();
          return;
        }
        event.preventDefault();
        scrollToTarget(target);
        setActive(guide, link.__qIndex);
      });

      if (!target) return;

      link.addEventListener('mouseenter', function() {
        target.classList.add('q-guide-hint');
      });

      link.addEventListener('mouseleave', function() {
        target.classList.remove('q-guide-hint');
      });

      link.addEventListener('focus', function() {
        target.classList.add('q-guide-hint');
      });

      link.addEventListener('blur', function() {
        target.classList.remove('q-guide-hint');
      });
    });

    setupStarfield(guide);
    setActive(guide, 0);
  }

  function init() {
    document.querySelectorAll('[data-q-guide]').forEach(bindGuide);
    updateAll();
  }

  if (!window.__qGuideScrollBound) {
    window.__qGuideScrollBound = true;
    window.addEventListener('scroll', requestUpdate, { passive: true });
    window.addEventListener('resize', requestUpdate);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  document.addEventListener('pjax:complete', init);
})();
