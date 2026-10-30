'use strict';

/**
 * NexT -> Butterfly 标签兼容层。
 *
 * 文章正文沿用了 NexT 的写法：
 *   - {% label danger@失败 %}
 *   - {% note info **Q1：...** %}...{% endnote %}  （可折叠问答）
 *
 * Butterfly 的 label 参数顺序不同，note 也不支持带标题的折叠形式。
 * 这里在渲染前做一次转换，正文无需逐篇修改。
 */

const TITLED_NOTE = /{%\s*note\s+(primary|info|success|warning|danger|default)\s+((?:(?!%}|\n).)+?)\s*%}([\s\S]*?){%\s*endnote\s*%}/g;
const LABEL = /{%\s*label\s+([a-zA-Z-]+)@((?:(?!%}|\n).)+?)\s*%}/g;

// 只处理代码块之外的文本，避免把示例代码里的标签也改掉
function transformOutsideCode(content, fn) {
  const parts = content.split(/(```[\s\S]*?```|~~~[\s\S]*?~~~)/g);
  return parts.map((part, index) => index % 2 === 1 ? part : fn(part)).join('');
}

hexo.extend.filter.register('before_post_render', function(data) {
  if (!data.content) return data;

  data.content = transformOutsideCode(data.content, function(text) {
    return text
      .replace(TITLED_NOTE, function(_, type, title, body) {
        return `{% notedetails ${type} ${title.trim()} %}${body}{% endnotedetails %}`;
      })
      .replace(LABEL, function(_, color, label) {
        return `{% label ${label.trim()} ${color} %}`;
      });
  });

  return data;
});

hexo.extend.tag.register('notedetails', function(args, content) {
  const type = args.shift() || 'info';
  const title = args.join(' ');
  const renderedTitle = hexo.render.renderSync({ text: title, engine: 'markdown' });
  const renderedContent = hexo.render.renderSync({ text: content, engine: 'markdown' });

  return `<details class="note nx-note ${type}">
<summary>${renderedTitle}</summary>
<div class="nx-note__body">${renderedContent}</div>
</details>`;
}, { ends: true });
