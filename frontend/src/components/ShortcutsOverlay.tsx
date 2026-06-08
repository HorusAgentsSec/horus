import { useEffect, useState, useRef } from 'react';

export function ShortcutsOverlay() {
  const [active, setActive] = useState(false);
  const [elements, setElements] = useState<{el: HTMLElement, key: string, rect: DOMRect}[]>([]);
  
  const activeRef = useRef(active);
  const elementsRef = useRef(elements);

  useEffect(() => {
    activeRef.current = active;
    elementsRef.current = elements;
  }, [active, elements]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Shift' && !e.repeat && !e.ctrlKey && !e.altKey && !e.metaKey) {
        setActive(true);
        const clickable = Array.from(document.querySelectorAll('button, a, [role="button"]'))
            .filter(el => {
                const r = el.getBoundingClientRect();
                return r.width > 0 && r.height > 0 && r.top >= 0 && r.left >= 0 && r.bottom <= window.innerHeight && r.right <= window.innerWidth;
            }) as HTMLElement[];
        
        const chars = '1234567890QWERTYUIOPASDFGHJKLZXCVBNM';
        const els = clickable.map((el, i) => ({
            el,
            key: chars[i % chars.length],
            rect: el.getBoundingClientRect()
        }));
        setElements(els);
      }
      
      if (activeRef.current && e.key !== 'Shift') {
        const char = e.key.toUpperCase();
        const target = elementsRef.current.find(item => item.key === char);
        if (target) {
            e.preventDefault();
            e.stopPropagation();
            target.el.click();
            setActive(false);
        }
      }
    };

    const handleKeyUp = (e: KeyboardEvent) => {
      if (e.key === 'Shift') {
        setActive(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown, { capture: true });
    window.addEventListener('keyup', handleKeyUp, { capture: true });
    return () => {
      window.removeEventListener('keydown', handleKeyDown, { capture: true });
      window.removeEventListener('keyup', handleKeyUp, { capture: true });
    };
  }, []);

  if (!active) return null;

  return (
    <div className="fixed inset-0 z-[9999] pointer-events-none">
      {elements.map((item, idx) => (
        <div
          key={idx}
          className="absolute bg-white text-black text-[10px] font-bold px-1.5 py-0.5 rounded shadow-lg border border-black/20"
          style={{
            top: item.rect.top + item.rect.height / 2 - 10,
            left: item.rect.left + item.rect.width / 2 - 10,
          }}
        >
          {item.key}
        </div>
      ))}
    </div>
  );
}
