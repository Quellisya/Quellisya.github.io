'use strict';

/**
 * 系列导航。
 *
 * 同一 series 的文章会自动生成一个导航块，插在正文最前面：
 *   - 显示「第 N / M 篇」
 *   - 列出本系列全部文章（当前篇高亮）
 *   - 给出上一篇 / 下一篇链接
 *
 * 排序依据 series_order（没有就退回发布时间）。
 * 新增文章只要在 front-matter 里写 series 和 series_order 即可，不需要改这里。
 */
hexo.extend.filter.register('after_render:html', function(html, locals) {
  const page = locals && locals.page;
  if (!page || !page.series) return html;

  const { escapeHTML } = require('hexo-util');
  const root = hexo.config.root || '/';

  const url = function(path) {
    if (!path) return '#';
    if (/^(https?:)?\/\//.test(path) || path.charAt(0) === '#') return path;
    return (root.endsWith('/') ? root : root + '/') + String(path).replace(/^\/+/, '');
  };

  const esc = function(value) {
    return escapeHTML(value == null ? '' : String(value));
  };

  const order = function(post) {
    const value = Number(post.series_order);
    return Number.isFinite(value) ? value : 9999;
  };

  const members = hexo.locals.get('posts')
    .filter(post => post.series === page.series)
    .toArray()
    .sort((a, b) => order(a) - order(b) || a.date - b.date);

  if (members.length < 2) return html;

  const index = members.findIndex(post => post.path === page.path);
  if (index < 0) return html;

  const items = members.map((post, i) => {
    const current = i === index ? ' class="is-current"' : '';
    return `<li${current}><a href="${esc(url(post.path))}">${esc(post.title)}</a></li>`;
  }).join('');

  const prev = members[index - 1];
  const next = members[index + 1];
  const arrows = [
    prev ? `<a class="series-nav__prev" href="${esc(url(prev.path))}"><i class="fa fa-arrow-left"></i>${esc(prev.title)}</a>` : '',
    next ? `<a class="series-nav__next" href="${esc(url(next.path))}">${esc(next.title)}<i class="fa fa-arrow-right"></i></a>` : ''
  ].join('');

  const nav = `
<nav class="series-nav">
  <div class="series-nav__head">
    <i class="fa fa-layer-group"></i>
    <span class="series-nav__name">系列：${esc(page.series)}</span>
    <span class="series-nav__count">第 ${index + 1} / ${members.length} 篇</span>
  </div>
  <ol class="series-nav__list">${items}</ol>
  ${arrows ? `<div class="series-nav__links">${arrows}</div>` : ''}
</nav>`;

  return html.replace(/(<div class="post-body[^"]*"[^>]*>)/, '$1' + nav);
}, 10);
