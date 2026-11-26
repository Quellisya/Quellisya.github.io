(function() {
  'use strict';

  var reduceMotion = window.matchMedia
    && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var ticking = false;

  function normalize(text) {
    return String(text || '').replace(/\s+/g, '').trim();
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
