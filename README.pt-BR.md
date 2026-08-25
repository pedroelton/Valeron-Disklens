# DiskLens

**Veja o que está ocupando seu disco e limpe com segurança.**

O DiskLens varre uma unidade e mostra, numa interface no navegador, para onde o espaço foi: as maiores pastas e arquivos, os caches que o sistema recria sozinho, duplicados de verdade comparados pelo conteúdo e arquivos grandes que você parou de usar.

É um único arquivo Python mais três arquivos estáticos. Nada para instalar, sem conta, sem telemetria, sem acesso à internet.

- Idiomas: inglês e português, alternáveis na interface
- Plataformas: Windows (recursos completos), Linux e macOS (varredura e duplicados)
- Requisito: Python 3.8 ou superior

---

## Começando

### Windows

1. [Instale o Python](https://www.python.org/downloads/) se ainda não tiver. Marque **Add python.exe to PATH** durante a instalação.
2. Baixe este repositório (botão verde **Code**, depois **Download ZIP**) e extraia.
3. Dê dois cliques em **`run-windows.bat`**. Ele pede permissão de administrador e abre a interface.

Administrador não é obrigatório, mas sem isso a varredura não consegue ler pastas de sistema, que é justamente onde um disco cheio costuma esconder o problema.

### Linux e macOS

```bash
python3 disklens.py --path ~
```

Depois abra a URL que aparece no terminal.

---

## O que cada aba mostra

| Aba | O que você vê |
|---|---|
| **Diagnóstico** | Espaço livre, quanto dá para recuperar e quanto do disco a varredura não conseguiu enxergar |
| **Limpeza rápida** | Caches e sobras conhecidas, já medidas, marcadas por risco |
| **Pastas** | Maiores pastas, com filtro e seletor de profundidade |
| **Arquivos** | Maiores arquivos individuais |
| **Duplicados** | Grupos de arquivos idênticos, com a primeira cópia protegida |
| **Antigos** | Arquivos acima de 100 MB parados há mais de um ano |

---

## Modelo de segurança

Limpadores de disco têm má fama porque a maioria apaga primeiro e explica depois. O DiskLens faz o contrário.

**Nada é apagado sem você marcar e confirmar.** Não existe modo automático nem botão de limpar tudo.

**Três níveis de risco, sempre visíveis:**

| Nível | Significado |
|---|---|
| `seguro` | O sistema ou o programa recria sozinho. Nada quebra. |
| `cuidado` | Também é recriável, mas custa tempo ou download. Exemplo: cache de pacotes, dados de mercado baixados. |
| `info` | O DiskLens se recusa a mexer. A interface mostra o comando correto. |

**Lixeira por padrão.** As exclusões vão para a lixeira pela API nativa do Windows, então dá para restaurar. A exclusão permanente fica desativada, a menos que você inicie com `--allow-permanent`.

**Caminhos protegidos são recusados no servidor**, mesmo que você force: pastas de sistema do Windows, WinSxS, Program Files, suas pastas pessoais e os arquivos `pagefile.sys`, `hiberfil.sys` e `swapfile.sys`.

**Junctions e symlinks nunca são seguidos**, o que evita loops infinitos e a contagem em dobro que faz outras ferramentas reportarem tamanhos impossíveis.

---

## Segurança

A interface é uma página web local, ou seja, um site malicioso poderia em tese tentar conversar com ela pelo seu navegador. Três camadas impedem isso:

1. **Token de sessão.** Um token aleatório é gerado ao iniciar, injetado na página e exigido em toda chamada de API. Uma requisição de outra origem não consegue lê-lo.
2. **Validação de Host.** Requisições cujo cabeçalho `Host` não seja `127.0.0.1` ou `localhost` na porta esperada são recusadas, o que bloqueia DNS rebinding.
3. **Validação de Origin.** Quando o cabeçalho `Origin` existe, ele precisa apontar para este servidor.

O servidor escuta apenas em `127.0.0.1`. Nunca fica acessível pela sua rede.

---

## Como os duplicados são detectados

Três passagens, da mais barata para a mais cara:

1. Agrupa por tamanho exato.
2. Faz hash dos primeiros e últimos 64 KB de cada candidato.
3. Faz hash do conteúdo inteiro do que sobrou.

Só o que é idêntico byte a byte aparece como `exata`. Arquivos acima de 2 GB são comparados por amostragem para manter a varredura rápida, e vêm marcados como tal. O primeiro arquivo de cada grupo é sempre mantido e não pode ser marcado.

---

## Opções de linha de comando

```
python disklens.py [opções]

  --path CAMINHO         unidade ou pasta a varrer primeiro (padrão: C:\ no Windows)
  --port PORTA           porta local (padrão: 8765)
  --min-dup MB           tamanho mínimo ao procurar duplicados (padrão: 5)
  --max-hash-gb GB       acima disso, compara por amostragem (padrão: 2)
  --allow-permanent      habilita exclusão permanente (padrão: só lixeira)
  --auto                 já inicia a varredura
  --no-browser           não abre o navegador
  --version              mostra a versão e sai
```

---

## O que o DiskLens não faz por você

Alguns dos maiores consumidores de espaço no Windows não podem ser resolvidos apagando arquivos, porque o sistema os mantém abertos. O DiskLens mede e mostra o comando certo:

| Item | Comando |
|---|---|
| Arquivo de hibernação | `powercfg /h off` |
| Repositório de componentes | `DISM /Online /Cleanup-Image /StartComponentCleanup` |
| Pontos de restauração | `vssadmin list shadowstorage` |
| Arquivo de paginação | Propriedades do Sistema, Avançado, Desempenho, Memória virtual |
| Disco virtual do Docker | `docker system prune -a`, depois compacte o vhdx |

---

## Perguntas frequentes

**Apaguei coisas e o espaço livre não mudou.**
Os itens foram para a lixeira. Use o botão **Esvaziar lixeira** no topo.

**A varredura diz 200 GB usados mas só achou 150 GB.**
A diferença aparece na aba Diagnóstico como *Não visto pela varredura*. Costuma ser arquivo de paginação, pontos de restauração ou pastas sem permissão de leitura. Rode como administrador e analise de novo.

**É seguro apagar tudo que está marcado como `seguro`?**
Sim, é exatamente isso que o rótulo quer dizer. Você pode precisar fazer login de novo em alguns sites, e o primeiro boot depois de limpar o Prefetch fica um pouco mais lento.

**Posso rodar num servidor ou compartilhar a porta?**
Não. Ele escuta em localhost por design e não tem autenticação além do token local. Não exponha.

---

## Contribuindo

Issues e pull requests são bem-vindos. A contribuição mais útil é um novo alvo de limpeza: adicione em `junk_targets()` no `disklens.py` com id, nível de risco e uma nota honesta sobre o que acontece ao remover, depois adicione a tradução em `JUNK_PT` no `app.js`.

Regras para novos alvos: nunca coloque no nível `safe` algo que o usuário não consiga recuperar de graça, e nunca adicione um caminho dentro de local protegido.

---

## Licença

MIT. Veja [LICENSE](LICENSE).

**Este software apaga arquivos.** Ele tem proteções, mas você é responsável pelo que seleciona. Leia o que cada alvo faz antes de remover e mantenha backup do que você não pode perder.
