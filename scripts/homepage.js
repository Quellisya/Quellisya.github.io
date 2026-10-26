'use strict';

/**
 * 在首页插入欢迎区与文章索引卡片。
 * 文案在 source/_data/homepage.yml 中维护。
 *
 * 文章索引是根据 _posts 自动生成的：新增文章后无需改这里，
 * 只要在 front-matter 里补上 topic / difficulty，首页会自动更新。
 */
hexo.extend.filter.register('after_render:html', function(html, locals) {
  if (!locals || locals.path !== 'index.html') return html;

  const { escapeHTML } = require('hexo-util');
  const data = (hexo.locals.get('data') || {}).homepage || {};
  const posts = hexo.locals.get('posts').sort('-date').toArray();
  const writeups = posts.filter(post => post.categories
    && post.categories.toArray().some(category => category.name === 'CTF'));

  const root = hexo.config.root || '/';

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
    return post.topic || firstTag(post) || 'Writeup';
  };

  const readingTime = function(post) {
    const plain = String(post.content || '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&[a-z]+;/gi, ' ');
    const cjk = (plain.match(/[一-龥]/g) || []).length;
    const words = (plain.replace(/[一-龥]/g, ' ').match(/[A-Za-z0-9_]+/g) || []).length;
    return Math.max(1, Math.round(cjk / 400 + words / 200));
  };

  const buttons = Array.isArray(data.buttons) && data.buttons.length
    ? data.buttons
    : [
      { text: '浏览全部 Writeup', link: '/categories/CTF/', icon: 'fa fa-flag', primary: true },
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

  const latest = writeups[0] || posts[0];
  const meta = latest
    ? `<div class="home-hero__meta"><span>已整理 <strong>${writeups.length}</strong> 篇 Writeup</span><span>最近更新 <strong>${latest.date.format('YYYY-MM-DD')}</strong></span></div>`
    : '';

  // 从 Writeup 的主题字段里归并出关注方向，作为快捷入口
  const topicMap = new Map();
  (writeups.length ? writeups : posts).forEach(post => {
    const name = topicOf(post);
    if (!name || name === 'Writeup') return;
    const tag = post.tags ? post.tags.toArray().find(item => item.name === name) : null;
    const item = topicMap.get(name) || {
      name: name,
      path: tag ? tag.path : '/tags/',
      count: 0
    };
    item.count += 1;
    topicMap.set(name, item);
  });
  const topics = [...topicMap.values()]
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, 8);
  const tagHtml = topics.length
    ? `<div class="home-hero__tags"><span>关注方向</span>${topics.map(topic => `<a href="${esc(url(topic.path))}">${esc(topic.name)}</a>`).join('')}</div>`
    : '';

  // 文章索引卡片
  const cards = (writeups.length ? writeups : posts).map(post => {
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
  }).join('');

  const cardSection = cards
    ? `<div class="home-section-head">
  <h2>${esc(data.index_title || '文章总览')}</h2>
  <a href="${esc(url('/archives/'))}">按时间浏览 →</a>
</div>
<div class="home-posts">${cards}</div>`
    : `<div class="home-empty">还没有文章，去写第一篇吧。</div>`;

  const hero = `
<section class="home-hero">
  <p class="home-hero__eyebrow">${esc(data.eyebrow || 'CTF · WEB SECURITY · NOTES')}</p>
  <h2 class="home-hero__title">${esc(data.title || '你好，我是 Quellisya')}</h2>
  <p class="home-hero__desc">${esc(data.description || '这里记录我的 CTF 与 Web 安全学习笔记。')}</p>
  <div class="home-hero__actions">${buttonHtml}</div>
  ${meta}
  ${tagHtml}
</section>
${cardSection}`;

  html = html.replace(/(<div class="main-inner[^"]*">)/, match => match + hero);

  // 首页已经用卡片展示全部文章，移除默认的文章列表与分页，避免重复
  html = html.replace(/<div class="post-block">[\s\S]*?<\/article>\s*<\/div>/g, '');
  html = html.replace(/<nav class="pagination">[\s\S]*?<\/nav>/g, '');

  return html;
}, 9);
