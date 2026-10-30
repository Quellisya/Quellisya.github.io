'use strict';

/**
 * 首页：水墨科技风欢迎区 + 按主题分组的文章索引。
 *
 * 文章索引从 _posts 自动生成；新增文章只要在 front-matter 里补
 * topic / difficulty / series / series_order，首页会自动更新。
 */
hexo.extend.filter.register('after_render:html', function(html, locals) {
  if (!locals || locals.path !== 'index.html') return html;

  const { escapeHTML } = require('hexo-util');
  const data = (hexo.locals.get('data') || {}).homepage || {};
  const posts = hexo.locals.get('posts').sort('-date').toArray();
  const writeups = posts.filter(post => post.categories
    && post.categories.toArray().some(category => category.name === 'CTF'));

  const root = hexo.config.root || '/';
  const PER_TOPIC = 6;
  const NUMERALS = ['壹', '贰', '叁', '肆', '伍', '陆', '柒', '捌', '玖', '拾'];

  const url = function(path) {
    if (!path) return '#';
    if (/^(https?:)?\/\//.test(path) || path.charAt(0) === '#') return path;
    return (root.endsWith('/') ? root : root + '/') + String(path).replace(/^\/+/, '');
  };

  const esc = function(value) {
    return escapeHTML(value == null ? '' : String(value));
  };

  const firstTag = function(post) {
    const tags = post.tags ? post.tags.toArray() : [];
    return tags[0] ? tags[0].name : '';
  };

  const topicOf = function(post) {
    return post.topic || firstTag(post) || '其他';
  };

  const readingTime = function(post) {
    const plain = String(post.content || '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&[a-z]+;/gi, ' ');
    const cjk = (plain.match(/[一-龥]/g) || []).length;
    const words = (plain.replace(/[一-龥]/g, ' ').match(/[A-Za-z0-9_]+/g) || []).length;
    return Math.max(1, Math.round(cjk / 400 + words / 200));
  };

  const categories = hexo.locals.get('categories').toArray();
  const categoryPath = function(name) {
    const category = categories.find(item => item.name === name);
    if (category) return category.path;
    const tag = hexo.locals.get('tags').toArray().find(item => item.name === name);
    return tag ? tag.path : null;
  };

  const buttons = Array.isArray(data.buttons) && data.buttons.length
    ? data.buttons
    : [
      { text: '按分类浏览', link: '/categories/', icon: 'fas fa-layer-group', primary: true },
      { text: '文章归档', link: '/archives/', icon: 'fas fa-archive' },
      { text: 'GitHub', link: 'https://github.com/Quellisya', icon: 'fab fa-github', external: true }
    ];

  const buttonHtml = buttons.map(button => {
    const link = button.link || '#';
    const external = button.external || /^https?:\/\//.test(link);
    const className = 'home-hero__btn' + (button.primary ? ' home-hero__btn--primary' : '');
    const icon = button.icon ? `<i class="${esc(button.icon)}"></i>` : '';
    return `<a class="${className}" href="${esc(url(link))}"${external ? ' target="_blank" rel="noopener"' : ''}>${icon}<span>${esc(button.text)}</span></a>`;
  }).join('');

  // ---------- 按主题分组 ----------
  const source = writeups.length ? writeups : posts;
  const groupMap = new Map();
  source.forEach(post => {
    const name = topicOf(post);
    if (!groupMap.has(name)) groupMap.set(name, []);
    groupMap.get(name).push(post);
  });

  const groups = [...groupMap.entries()]
    .map(([name, items]) => ({ name, items, latest: items[0].date }))
    .sort((a, b) => b.items.length - a.items.length || b.latest - a.latest);

  const latest = source[0];

  // ---------- 主题快捷入口 ----------
  const chips = groups.map((group, i) =>
    `<a href="#topic-${i + 1}">${esc(group.name)}<em>${String(group.items.length).padStart(2, '0')}</em></a>`
  ).join('');

  // ---------- 卡片 ----------
  const card = function(post, index) {
    const topic = topicOf(post);
    const difficulty = post.difficulty || '';
    const tags = post.tags ? post.tags.toArray().slice(0, 3) : [];
    const summary = String(post.description || post.excerpt || '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    const metaLine = [
      `<span><i class="far fa-calendar-alt"></i>${esc(post.date.format('YYYY-MM-DD'))}</span>`,
      `<span><i class="far fa-clock"></i>${readingTime(post)} min</span>`
    ].join('');
    const seriesLine = post.series
      ? `<span><i class="fas fa-layer-group"></i>${esc(post.series)}${post.series_order != null ? ' · ' + String(post.series_order).padStart(2, '0') : ''}</span>`
      : '';
    const tagLine = tags.length
      ? `<div class="home-post-card__tags">${tags.map(tag => `<span>#${esc(tag.name)}</span>`).join('')}</div>`
      : '';

    return `
<a class="home-post-card q-tilt" href="${esc(url(post.path))}">
  <div class="home-post-card__head">
    <span class="home-post-card__index">${String(index + 1).padStart(2, '0')}</span>
    <span class="home-post-card__topic">${esc(topic)}</span>
    ${difficulty ? `<span class="home-post-card__level">${esc(difficulty)}</span>` : ''}
  </div>
  <h3 class="home-post-card__title">${esc(post.title)}</h3>
  <p class="home-post-card__desc">${esc(summary)}</p>
  <div class="home-post-card__meta">${metaLine}${seriesLine}</div>
  ${tagLine}
  <span class="home-post-card__more">阅读笔记 <i class="fas fa-arrow-right"></i></span>
</a>`;
  };

  // ---------- 每个主题一段 ----------
  const sections = groups.map((group, i) => {
    const shown = group.items.slice(0, PER_TOPIC).map(card).join('');
    const rest = group.items.length - Math.min(group.items.length, PER_TOPIC);
    const path = categoryPath(group.name);
    const more = path
      ? `<a class="home-section-head__more" href="${esc(url(path))}">${rest > 0 ? `还有 ${rest} 篇` : '查看全部'} <i class="fas fa-arrow-right"></i></a>`
      : '';
    return `<div class="home-section-head" id="topic-${i + 1}">
  <div class="home-section-head__title">
    <span class="home-section-head__numeral">${NUMERALS[i] || String(i + 1).padStart(2, '0')}</span>
    <h2>${esc(group.name)}</h2>
    <span class="home-section-head__count">${String(group.items.length).padStart(2, '0')}</span>
  </div>
  ${more}
</div>
<div class="home-posts">${shown}</div>`;
  }).join('');

  const meta = latest
    ? `<div class="home-hero__meta">
      <span><b>${String(source.length).padStart(2, '0')}</b> 篇笔记</span>
      <span><b>${String(groups.length).padStart(2, '0')}</b> 个主题</span>
      <span>更新于 <b>${latest.date.format('YYYY-MM-DD')}</b></span>
    </div>`
    : '';

  const tagHtml = chips
    ? `<div class="home-hero__tags"><span class="home-hero__tags-label">主题</span>${chips}</div>`
    : '';

  const body = sections || `<div class="home-empty">还没有文章，去写第一篇吧。</div>`;

  const hero = `
<div class="home-shell">
<style id="home-custom-guard">#recent-posts,#pagination{display:none!important}#content-inner{display:block!important;max-width:1280px!important}#content-inner>.home-shell{width:100%!important;max-width:100%!important;padding:0!important;background:none!important;box-shadow:none!important}#content-inner>.home-shell~#aside-content{display:none!important}</style>
<section class="home-hero">
  <div class="home-hero__wash" aria-hidden="true"></div>
  <div class="home-hero__inner">
    <div class="home-hero__copy">
      <p class="home-hero__eyebrow"><span class="home-hero__prompt">&gt;_</span>${esc(data.eyebrow || 'CTF · WEB SECURITY · NOTES')}</p>
      <h2 class="home-hero__title">${esc(data.title_prefix || '你好，我是')} <span class="home-hero__name">${esc(data.name || 'Quellisya')}</span></h2>
      <p class="home-hero__desc">${esc(data.description || '这里记录我的 CTF 与 Web 安全学习笔记。')}</p>
      <div class="home-hero__actions">${buttonHtml}</div>
      ${meta}
      ${tagHtml}
    </div>
    <aside class="home-hero__side" aria-hidden="true">
      <div class="home-seal">卷</div>
      <div class="home-terminal">
        <div class="home-terminal__bar"><i></i><i></i><i></i><span>quellisya@ctf</span></div>
        <pre class="home-terminal__body"><code><span class="home-terminal__prompt">$</span> whoami
Quellisya

<span class="home-terminal__prompt">$</span> cat /focus
CTF · Web Security

<span class="home-terminal__prompt">$</span> <span class="home-terminal__cursor">▮</span></code></pre>
      </div>
      <p class="home-hero__vertical">网络空间安全笔记</p>
    </aside>
  </div>
  <div class="home-hero__scroll"><span></span>向下阅读</div>
</section>
<div class="home-section-head home-section-head--overview">
  <div class="home-section-head__title">
    <span class="home-section-head__numeral">录</span>
    <h2>${esc(data.index_title || '文章总览')}</h2>
  </div>
  <a class="home-section-head__more" href="${esc(url('/archives/'))}">按时间浏览 <i class="fas fa-arrow-right"></i></a>
</div>
${body}
</div>`;

  html = html.replace(/(<main[^>]*id="content-inner"[^>]*>)/, match => match + hero);

  return html;
}, 9);
