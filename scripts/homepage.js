'use strict';

/**
 * 首页：欢迎区 + 按主题分组的文章索引。
 * 文案在 source/_data/homepage.yml 中维护。
 *
 * 文章索引根据 _posts 自动生成：新增文章后无需改这里，
 * 只要在 front-matter 里补上 topic / difficulty / series_order，首页会自动更新。
 *
 * 分组规则：按 topic 聚合。每个主题展示最近 N 篇，超过则给出「查看全部」。
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

  // 分类对象，用来给「查看全部」找链接
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
      { text: '按分类浏览', link: '/categories/', icon: 'fa fa-th', primary: true },
      { text: '文章归档', link: '/archives/', icon: 'fa fa-archive' },
      { text: 'GitHub', link: 'https://github.com/Quellisya', icon: 'fa fa-github', external: true }
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

  // 主题按「最近一篇的发布时间」倒序
  const groups = [...groupMap.entries()]
    .map(([name, items]) => ({ name, items, latest: items[0].date }))
    .sort((a, b) => b.latest - a.latest);

  const latest = source[0];

  // ---------- 主题快捷入口 ----------
  const chips = groups.map((group, i) =>
    `<a href="#topic-${i + 1}">${esc(group.name)}<span>${group.items.length}</span></a>`
  ).join('');

  // ---------- 卡片 ----------
  const card = function(post) {
    const topic = topicOf(post);
    const difficulty = post.difficulty || '';
    const tags = post.tags ? post.tags.toArray().slice(0, 3) : [];
    const summary = String(post.description || post.excerpt || '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    const metaLine = [
      `<span><i class="far fa-calendar"></i>${esc(post.date.format('YYYY-MM-DD'))}</span>`,
      `<span><i class="far fa-clock"></i>约 ${readingTime(post)} 分钟</span>`
    ].join('');
    const tagLine = tags.length
      ? `<div class="home-post-card__tags">${tags.map(tag => `<span>#${esc(tag.name)}</span>`).join('')}</div>`
      : '';
    return `
<a class="home-post-card" href="${esc(url(post.path))}">
  <div class="home-post-card__head">
    <span class="home-post-card__topic">${esc(topic)}</span>
    ${difficulty ? `<span class="home-post-card__level">${esc(difficulty)}</span>` : ''}
  </div>
  <h3 class="home-post-card__title">${esc(post.title)}</h3>
  <p class="home-post-card__desc">${esc(summary)}</p>
  <div class="home-post-card__meta">${metaLine}</div>
  ${tagLine}
</a>`;
  };

  // ---------- 每个主题一段 ----------
  const sections = groups.map((group, i) => {
    const shown = group.items.slice(0, PER_TOPIC).map(card).join('');
    const rest = group.items.length - group.items.slice(0, PER_TOPIC).length;
    const path = categoryPath(group.name);
    const more = path
      ? `<a href="${esc(url(path))}">${rest > 0 ? `还有 ${rest} 篇 →` : '查看全部 →'}</a>`
      : '';
    return `<div class="home-section-head" id="topic-${i + 1}">
  <h2>${esc(group.name)}<span class="home-section-head__count">${group.items.length} 篇</span></h2>
  ${more}
</div>
<div class="home-posts">${shown}</div>`;
  }).join('');

  const meta = latest
    ? `<div class="home-hero__meta"><span>已整理 <strong>${source.length}</strong> 篇</span><span>共 <strong>${groups.length}</strong> 个主题</span><span>最近更新 <strong>${latest.date.format('YYYY-MM-DD')}</strong></span></div>`
    : '';

  const tagHtml = chips
    ? `<div class="home-hero__tags"><span>主题</span>${chips}</div>`
    : '';

  const body = sections || `<div class="home-empty">还没有文章，去写第一篇吧。</div>`;

  const hero = `
<section class="home-hero">
  <p class="home-hero__eyebrow">${esc(data.eyebrow || 'CTF · WEB SECURITY · NOTES')}</p>
  <h2 class="home-hero__title">${esc(data.title || '你好，我是 Quellisya')}</h2>
  <p class="home-hero__desc">${esc(data.description || '这里记录我的 CTF 与 Web 安全学习笔记。')}</p>
  <div class="home-hero__actions">${buttonHtml}</div>
  ${meta}
  ${tagHtml}
</section>
${body}`;

  html = html.replace(/(<div class="main-inner[^"]*">)/, match => match + hero);

  // 首页已经用卡片展示文章，移除主题默认列表与分页，避免重复
  html = html.replace(/<div class="post-block">[\s\S]*?<\/article>\s*<\/div>/g, '');
  html = html.replace(/<nav class="pagination">[\s\S]*?<\/nav>/g, '');

  return html;
}, 9);
