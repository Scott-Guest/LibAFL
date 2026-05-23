# First-Class Generative Blackbox Fuzzing in LibAFL

## 1. Motivation

LibAFL's paper presents it as "a *family* of testing techniques which
repeatedly provide machine-generated input data to a target system" and
identifies nine entities that recur across modern fuzzers: Input, Corpus,
Scheduler, Stage, Observer, Executor, Feedback, Mutator, Generator.

In practice, however, the entire framework — and especially the way these
entities interlock — is shaped by **mutation-based, feedback-driven, coverage-
guided** fuzzing. The Stage drives a Mutator over a Corpus entry; the Mutator
operates on a byte-like Input; the Feedback grades the run against an
Observer that almost always reflects target-side coverage; the Scheduler
picks the next *existing* corpus entry. `Generator` is present, but it is
the least-developed entity in the system: it produces an Input from nothing,
period.

**Generative blackbox fuzzers** — Csmith, YarpGen, jsfunfuzz, libfuzzer-pro,
Hypothesis, Crowbar, tree-guide-style fuzzers — invert most of this picture:

- The *generator* is the centerpiece. It encodes domain validity (a Csmith
  program is well-typed and side-effect-free; a yarpgen program respects
  language semantics that catch real compiler bugs).
- There is no coverage feedback. Validity, divergence, or differential
  outputs drive interestingness.
- The natural "input" is **the sequence of random choices the generator
  made**, not the bytes the target eventually saw. A choice sequence is
  small, reproducible, mutatable, and shrinkable.
- Sophisticated guides (BFS over the decision tree, weighted cardinality
  estimation, exhaustive enumeration, replay from disk, parallel
  round-robin) are *interchangeable* strategies sitting behind one
  interface. The user generator code does not change when a guide is
  swapped.

The goal of this document is to identify the smallest set of additive
abstractions that lets generative blackbox fuzzing **fall out of LibAFL's
existing compositional model**, in the same spirit as Section 4 of the paper.
We do not want a hardcoded "blackbox subsystem"; we want the right primitives
so that Csmith-on-LibAFL is a 200-line `fuzzers/generative/csmith/` example
that wires together off-the-shelf building blocks.

## 2. Reference points

### 2.1 LibAFL today

Concrete shape of the relevant traits (locations are `crates/libafl/src/`):

| Entity | Trait | Signature highlight |
|---|---|---|
| Input | `inputs::Input` | `Clone + Serialize + DeserializeOwned + Hash`, no methods required |
| Generator | `generators::Generator<I, S>` | `fn generate(&mut self, state: &mut S) -> Result<I, Error>` |
| Mutator | `mutators::Mutator<I, S>` | `fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, Error>` |
| Stage | `stages::Stage<E, EM, S, Z>` | `fn perform(&mut self, fuzzer, executor, state, manager)` |
| Feedback | `feedbacks::Feedback<EM, I, OT, S>` | `is_interesting(...) -> bool` |
| Scheduler | `schedulers::Scheduler<I, S>` | `next(&mut self, state) -> Result<CorpusId, Error>` |
| Executor | `executors::Executor<EM, I, S, Z>` | `run_target(...) -> Result<ExitKind, Error>` |
| Observer | `observers::Observer<I, S>` | `pre_exec/post_exec` |

Existing generative support consists of:

- `GenStage` (`stages/generation.rs`): runs `generator.generate(state)` once
  and feeds the result through `Evaluator::evaluate_filtered`. ~50 lines.
- `RandBytesGenerator` / `RandPrintablesGenerator`: stateless RNG-driven
  byte generators.
- `GramatronGenerator` (`generators/gramatron.rs`): walks a deterministic
  pushdown automaton, using `state.rand_mut()` for branch choices, and
  produces a `GramatronInput` (a `Vec<Terminal>`).
- `NautilusGenerator` (`generators/nautilus.rs`): grammar-tree generator
  producing a `NautilusInput` (the AST itself is the input). Companion
  `NautilusRandomMutator`, `NautilusRecursionMutator`, `NautilusSpliceMutator`
  manipulate the tree.

These three pre-built generators are the entire current story for "fuzzers
where the input is more than bytes." They share a common shape that is
worth naming:

1. The generator's *random tape* (the bits consumed from `Rand` during
   generation) is the latent input.
2. The generator emits a structured representation (terminals, tree).
3. That structured representation is later serialized to target bytes via
   `ToTargetBytesConverter`.

But nothing in the framework expresses (1). The latent choice sequence is
implicit, sunk into the RNG, and unrecoverable. As a result, generators
cannot be combined with strategies that need to *observe and direct* the
choices.

### 2.2 tree-guide (Regehr et al.)

`include/guide.h` is one header that defines two traits:

```cpp
class Chooser {
public:
  virtual uint64_t choose(uint64_t n) = 0;             // [0, n)
  virtual bool     flip() = 0;
  virtual uint64_t chooseWeighted(const vector<double>& w) = 0;
  virtual uint64_t chooseUnimportant() = 0;            // doesn't branch the tree
  virtual void     beginScope() = 0;
  virtual void     endScope() = 0;
};

class Guide {
public:
  virtual unique_ptr<Chooser> makeChooser() = 0;
};
```

Generators are written **once** against `Chooser`, e.g.:

```cpp
string gen(Chooser& C, long depth) {
  C.beginScope();
  switch (C.choose(11)) {
    case 0: return chr(C);
    case 1: return gen(C, depth-1) + "|" + gen(C, depth-1);
    ...
  }
  C.endScope();
}
```

The strategy is selected by which `Guide` mints choosers:

- `DefaultGuide`: thin wrapper over an `mt19937_64`. (~baseline random)
- `BFSGuide`: maintains the decision tree, explores breadth-first, falls
  back to random past the frontier.
- `EnumeratingGuide`: depth-first exhaustive walk.
- `WeightedSamplerGuide`: cardinality-estimating biased exploration that
  rebalances `SizeEstimate`s after each run.
- `SaverGuide`: wraps any other guide and records the choice sequence so it
  can be persisted.
- `FileGuide`: replays a previously-saved choice sequence. Tolerates
  out-of-range and exhausted-tape conditions (`Sync::NONE`, `RESYNC`,
  `BALANCE`) — i.e., generators are robust under arbitrary mutations of the
  tape.
- `RRGuide`: round-robins between several guides.

The `mutate/mutate.cpp` shim picks a random `RecKind::NUM` entry in a saved
sequence and replaces its value uniformly. The AFL++ plug-in
(`aflplusplus/guide-gen.cpp`) wires this into AFL++'s custom mutator
API: parse choice file → mutate a number → invoke the user generator
binary with `FILEGUIDE_INPUT_FILE`/`FILEGUIDE_OUTPUT_FILE` → return the
generator's stdout as the test case.

The core idea is **separation of choice resolution from generation**: the
generator body never asks where its random bits come from.

### 2.3 Csmith

`AbsRndNumGenerator` is csmith's analogue of `Chooser`:

```cpp
virtual unsigned int rnd_upto(unsigned int n, const Filter* f, const string* where) = 0;
virtual bool         rnd_flipcoin(unsigned int p, const Filter* f, const string* where) = 0;
virtual string       RandomDigits(int num) = 0;
virtual void         get_sequence(string& s) = 0;
```

Two implementations: `DefaultRndNumGenerator` (random + sequence logging)
and `DFSRndNumGenerator` (systematic backtracking search with eager
backtracking when no choice satisfies the filter). Csmith uses these
all over the place; `Function.cpp` example: `rnd_flipcoin(InlineFunctionProb())`.

Two features beyond tree-guide are worth noting:

1. **`Filter`** — at a choice point the user supplies a predicate that
   rules out specific values in context. Lets the strategy avoid wasted
   work (the DFS generator can backtrack instead of always emitting
   invalid choices and rejecting).
2. **`where` / static choice point identity** — the call site is tagged so
   a strategy can decide whether two textually-same choice points are "the
   same node" in the tree.

## 3. What's missing in LibAFL today

The mismatch is not that LibAFL *can't* express generative blackbox fuzzing.
It is that doing so requires every author to invent the same five
infrastructure pieces in private. The paper's central claim — that
orthogonal techniques should compose — fails for this corner of the design
space.

### Gap 1 — No `Chooser` abstraction

A LibAFL `Generator` is a function `&mut S -> I`. Inside the body, the
author reaches into `state.rand_mut()` directly. This pinions the choice
strategy to whatever the State's `Rand` is. There is no way to pass in a
chooser that, e.g., consults a BFS frontier or replays a saved tape, short
of rewriting the generator.

This is the single highest-leverage gap. Every other gap in this list
either dissolves or shrinks once a Chooser trait exists.

### Gap 2 — Choice sequences are not first-class inputs

The `Input` trait is byte-agnostic, which is good. But the *one* input shape
that recurs across generative blackbox fuzzers — a serialized record of
"I picked branch i out of n at scope depth d" — has no canonical
representation in LibAFL. Nautilus and Gramatron each invent their own
(NautilusInput = AST; GramatronInput = Vec<Terminal>). These are
structured inputs, not choice sequences, and the framework offers no
shared building blocks for either.

A `ChoiceSeq` input type, plus mutators on it, would be reusable across
every generative fuzzer.

### Gap 3 — Generators are fire-and-forget; guides are stateful

`Generator::generate` is a one-shot call. There is no place for a guide
that *learns* between calls — accumulating tree shape, refining weight
estimates, advancing a BFS frontier — to live, except by stuffing state
into the State's `Metadata` map and pulling it back out.

You can fake it: stash a `RefCell<BfsGuideState>` in `state.metadata_mut()`
and have your generator consult it. That works mechanically, but it isn't
a contract. Other LibAFL components (a Stage wanting to ask "is the guide
exhausted?", a Scheduler wanting to interleave a corpus and a guide) can't
discover or compose with it.

### Gap 4 — `GenStage` is a fixed-budget loop

`stages/generation.rs` runs `generate` exactly once per stage execution and
hands the result to the evaluator. There is no concept of:

- "the guide is exhausted; stop" (the BFS finishing case)
- "this attempt was rejected by the generator itself; sample again without
  counting it" (csmith rejection rates can exceed 90%)
- "the guide produced a chooser that drove a generator that produced a
  testcase; remember the chooser for later mutation"

The natural shape of a generative loop is

```
while not exhausted:
    chooser = guide.make_chooser()
    case = user_generator(chooser)?            # may reject and resample
    exit = executor.run(case)
    guide.on_finished(chooser, exit, observers) # update internal model
    fuzzer.evaluate(...)
```

`GenStage` collapses all this into one straight line and drops everything
but the input.

### Gap 5 — No standard "convert choice sequence to bytes via a user generator"

Tree-guide-style mutation is:

1. Treat the corpus as `Corpus<ChoiceSeq>`.
2. Use a generic `ChoiceSeqMutator` to perturb a sequence.
3. To execute: replay the sequence through the user generator (under a
   `ReplayChooser`) to obtain the actual bytes the target consumes.

Step (3) is a `ToTargetBytesConverter<ChoiceSeq, S>` — but the converter
needs to hold a reference to the user generator, which means the user
generator must be invocable from a converter, which means it must be
written against an interface like `Chooser`. The pieces are all
constructible today, but the glue type — "a generator parameterized by its
choice source" — does not have a name in LibAFL.

### Gap 6 — `Filter`-style context-dependent rejection

Csmith's `rnd_upto(n, filter, where)` is the cleanest expression of "at
this choice point, in this context, options k1 and k2 are illegal." It
lets a DFS strategy skip provably-doomed branches instead of repeatedly
generating-and-discarding. Tree-guide does not have this; tree-guide pays
for it via more rejection sampling.

LibAFL has nothing here. A generative fuzzer that uses constraints
heavily (any real PL fuzzer) will want this primitive.

### Gap 7 — Schedulers are corpus-id-centric

`Scheduler<I, S>::next(&mut S) -> Result<CorpusId, Error>` mandates that
the next thing to fuzz is identified by a `CorpusId`. For a pure-guide
fuzzer there is no corpus entry; the guide *is* the source. For a hybrid
(corpus of crashing seeds + guide for exploration), there's no graceful
way to alternate.

This is the smallest gap on the list — a Stage can ignore the Scheduler —
but it forecloses the cleaner composition.

### Gap 8 — Observers/Feedback assume "target was run"

`Observer::pre_exec/post_exec` happen around the Executor. There's no
hook for "observe the act of generation." A generator-side observer
(e.g., "the AST contained a `volatile`") would be useful for:

- weight-tuning a guide based on what the generator produced
- counting generator-rejected attempts as a separate statistic
- triggering structure-aware feedbacks before/instead-of execution

This is the lowest-priority gap. It can be deferred until a concrete
fuzzer asks for it.

## 4. Proposed abstractions

The proposal is built on one new trait, `Chooser`, plus thin glue that
turns existing LibAFL entities into the right shape.

### 4.1 `Chooser`

Add `crates/libafl/src/choosers/mod.rs` (or in `libafl_bolts` alongside
`Rand`, since it's a primitive). Concretely:

```rust
pub trait Chooser {
    /// Return an index in [0, n).
    fn choose(&mut self, n: NonZeroUsize) -> Result<usize, Error>;

    /// Convenience: choose(2).
    fn flip(&mut self) -> Result<bool, Error> { Ok(self.choose(nonzero!(2))? != 0) }

    /// Weighted choice. Weights need not sum to 1.
    fn choose_weighted(&mut self, weights: &[f64]) -> Result<usize, Error>;

    /// A choice that does not structurally branch the decision tree
    /// (e.g., the value of a numeric literal in the output).
    fn choose_unimportant(&mut self) -> Result<u64, Error>;

    /// Open a structural scope. Mostly advisory: strategies may use it to
    /// align mutation/recombination boundaries; default impls are no-ops.
    fn begin_scope(&mut self) {}
    fn end_scope(&mut self) {}
}
```

Notes:

- It is **the only thing the user's generator code knows about.** No `S`,
  no `Rand`, no `State`. This is essential: a generator written against
  `Chooser` is reusable under any strategy.
- The `Result` return is for replay-from-bytes implementations that may
  hit malformed data; the trivial Rand-backed implementation will never
  error.
- A blanket impl `impl<R: Rand> Chooser for RandChooser<R>` recovers
  today's "just consume RNG" behavior. Existing generators that prefer
  the `Rand` interface continue to work unchanged.

Optionally, add a *context-aware* variant with the csmith `Filter`/`where`
machinery. This is significant enough scope that it should ship as a
follow-up trait `FilteringChooser` extending `Chooser`, not be folded into
the core.

### 4.2 `ChooserGenerator<I>`

Right next to the existing `Generator<I, S>`, add:

```rust
pub trait ChooserGenerator<I> {
    /// Produce one input using only the provided chooser as a randomness
    /// source. Implementations MUST be pure functions of the chooser's
    /// returned values (no internal RNG, no clock, no env reads). This
    /// determinism is the contract that makes replay, BFS, and choice-seq
    /// mutation work.
    fn generate<C: Chooser + ?Sized>(&mut self, chooser: &mut C) -> Result<I, GenError>;
}

pub enum GenError {
    /// This attempt is invalid (e.g., constraint failure). Caller should
    /// resample with a fresh chooser.
    Reject,
    /// Hard error.
    Fatal(Error),
}
```

The `Reject` variant is what lets the framework distinguish "the
generator gave up internally; redraw" from "the target crashed."

### 4.3 `Guide`

```rust
pub trait Guide<S> {
    type Chooser: Chooser;

    /// Mint a chooser for one generation attempt. Returns `Ok(None)` when
    /// the guide has nothing left to explore (BFS done, file exhausted,
    /// etc.). The Stage decides how to react.
    fn make_chooser(&mut self, state: &mut S) -> Result<Option<Self::Chooser>, Error>;

    /// Inform the guide what happened with a chooser it minted. The guide
    /// may inspect any internal state the chooser collected (typical
    /// impl: the chooser is consumed and its trail is folded back into
    /// the guide's data structures).
    fn on_finished(
        &mut self,
        state: &mut S,
        chooser: Self::Chooser,
        outcome: GenOutcome,
    ) -> Result<(), Error>;
}

pub enum GenOutcome {
    /// The generator rejected this chooser.
    Rejected,
    /// The generator produced a test case; the executor ran it. The
    /// guide can decide to weight by exit kind, or ignore.
    Executed { exit_kind: ExitKind /* ... */ },
}
```

The `on_finished` hook is what makes BFS, WeightedSampler, etc. fit. It
takes the chooser back: the BFS guide reads `chooser.path` to extend the
frontier; the WeightedSampler reads `chooser.trail` to update size
estimates. A trivial guide (`RandGuide`) ignores it.

Off-the-shelf guides to ship in tree (mirroring tree-guide):

- `RandGuide<R: Rand>` — wraps `state.rand_mut()`; never returns `None`.
- `BfsGuide` — owns the explored tree; `make_chooser` walks back from the
  highest-priority frontier node, returning a `ReplayThenRandomChooser`.
- `EnumeratingGuide` — DFS exhaustion.
- `WeightedSamplerGuide` — explore/exploit cardinality.
- `ReplayGuide` — yields choosers backed by a fixed `ChoiceSeq`.
- `SaverGuide<G>` — wraps another guide; choosers record the sequence.
- `RoundRobinGuide<[G; N]>`, `CorpusGuide<I>` — composition primitives.

### 4.4 `ChoiceSeq` as an `Input`

```rust
#[derive(Clone, Serialize, Deserialize, Hash, Debug)]
pub struct ChoiceSeq {
    pub records: Vec<ChoiceRecord>,
}

pub enum ChoiceRecord {
    Choice { n: u64, picked: u64 },      // choose(n) -> picked
    Weighted { picked: u64 },            // choose_weighted -> picked
    Unimportant { value: u64 },          // choose_unimportant -> value
    BeginScope,
    EndScope,
}

impl Input for ChoiceSeq {}
```

This is the canonical "input" for generative blackbox fuzzing in the same
way `BytesInput` is canonical for AFL-style fuzzing.

Pair it with:

- `ChoiceSeqMutator` family: `RandReplaceChoice`, `SpliceScope`,
  `DropScope`, `DuplicateScope`, `Shrink` (delete a record and re-derive).
  All operate on a `ChoiceSeq` without referring to the user generator.
- `ReplayChooser` impl that reads from a `ChoiceSeq` and falls back to
  random when exhausted or out-of-range (mirrors tree-guide's `FileGuide`
  with `Sync::BALANCE`).
- `SaverChooser<C>` that wraps any other chooser and records every call.

### 4.5 Bridging into existing LibAFL plumbing

The point of all the above is that **existing** LibAFL primitives consume
these new types unchanged:

- **`ToTargetBytesConverter<ChoiceSeq, S>`**: a `GeneratorBytesConverter<G>`
  holds a user `ChooserGenerator<MyAst>` plus an unparser
  `MyAst -> Vec<u8>`. To convert a `ChoiceSeq` to target bytes, replay
  the seq through a `ReplayChooser`, run the user generator, unparse.
  This lets a `ChoiceSeq` be the corpus input while the executor sees
  bytes — and *all existing executors work as-is.*

- **`MutationalStage<ChoiceSeq>`**: drop in a `ChoiceSeqMutator`. The
  existing mutational stage will mutate sequences and feed them to the
  converter without modification.

- **`Generator<MyAst, S>` for `GuidedGenerator<G, UG>`**: implementing
  the *existing* `Generator` trait by calling `guide.make_chooser` then
  `user.generate`. This means `GenStage`, `generate_initial_inputs`, and
  any other consumer of `Generator` work unchanged.

- **New `stages::guided::GuidedGenStage`**: same shape as `GenStage` but
  loops until the guide returns `None` or a budget elapses; threads
  rejections back into `Guide::on_finished`. Optionally saves the
  `ChoiceSeq` of interesting runs into the corpus as `ChoiceSeq` inputs.

- **No scheduler changes required.** A guide-only fuzzer can use a
  `NopCorpus` and `QueueScheduler` — the scheduler is never consulted by
  `GuidedGenStage`. A hybrid fuzzer uses a real corpus of `ChoiceSeq`
  inputs (with `MutationalStage` mutating them) and a `GuidedGenStage`
  in the same stage tuple. The two stages share nothing but `state`.

### 4.6 Sketch of the end-user wiring

```rust
// User code: their generator, written against Chooser.
struct MyCGenerator { /* ... */ }
impl ChooserGenerator<MyAst> for MyCGenerator { /* uses chooser only */ }

let user_gen = MyCGenerator::new();
let unparse  = |ast: &MyAst| ast.to_bytes();

// Pick a guide. Swap freely.
let mut guide = BfsGuide::new();
// or: WeightedSamplerGuide::new();
// or: RoundRobinGuide::new([Box::new(BfsGuide::new()), Box::new(CorpusGuide::new())]);

// Bridge into LibAFL.
let converter   = GeneratorBytesConverter::new(user_gen.clone(), unparse);
let gen_stage   = GuidedGenStage::new(guide, user_gen.clone());
let mut_stage   = StdMutationalStage::new(tuple_list!(
    RandReplaceChoiceMutator, SpliceScopeMutator, ShrinkMutator,
));

let mut fuzzer = StdFuzzer::builder()
    .scheduler(QueueScheduler::new())
    .feedback(DifferentialFeedback::new(/* compiler A vs B */))
    .objective(CrashFeedback::new())
    .target_bytes_converter(converter)
    .build();

let mut stages = tuple_list!(gen_stage, mut_stage);
fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
```

The user wrote one generator (against `Chooser`) and chose components.
Every line above is a building block already-in-tree under this proposal.

## 5. Non-additive changes (kept minimal)

The proposal is overwhelmingly additive, but two small adjustments are
defensible:

1. **`GenStage` learns the `None`-from-guide case.** Either generalize
   `GenStage` to consult a `Guide` (a thin refactor; `Generator` becomes
   a special case where the guide is `RandGuide`), or leave `GenStage`
   alone and ship `GuidedGenStage` alongside it. The latter is purely
   additive; the former is cleaner long-term and is the recommended
   approach. Either way the `Generator` trait keeps working.

2. **`Generator::generate` returning `Err` is currently treated as a hard
   failure** by `generate_initial_internal` (state/mod.rs:1055) and
   `GenStage`. For generative blackbox we want a "rejected, try again"
   variant. The cleanest path is to define `GenError` in `ChooserGenerator`
   (proposed in §4.2) and have `GuidedGenStage` distinguish `Reject` from
   `Fatal`. `Generator::generate`'s contract is untouched.

Everything else — `Input`, `Mutator`, `Stage`, `Feedback`, `Scheduler`,
`Executor`, `Observer`, `Corpus` — stays as-is.

## 6. What this is *not*

- **Not** a "blackbox subsystem." There is no `BlackboxFuzzer` type, no
  parallel pipeline, no second event loop. Everything plugs into the
  existing pipeline via existing entity slots. The only new traits
  (`Chooser`, `ChooserGenerator`, `Guide`) are primitives, not
  pipeline pieces.

- **Not** a grammar framework. Nautilus and Gramatron remain the
  grammar-fuzzing story. Generative blackbox is a *different* axis:
  it's about user-written imperative generators (Csmith, jsfunfuzz),
  not about grammars. The two can coexist; a Nautilus-derived generator
  can be written as a `ChooserGenerator` if someone wants
  guide-pluggability for it.

- **Not** tied to any one search strategy. BFS, weighted sampling, MCTS,
  pure-random, replay, round-robin all sit behind `Guide`. Adding a new
  strategy is one impl, zero plumbing.

- **Not** opinionated about how guides interact with feedback. The
  cheapest design (sketched here) passes `ExitKind` into
  `Guide::on_finished`. A richer design that lets a guide consume
  coverage observers is straightforward to layer on later.

## 7. Concrete next steps (rough order)

1. Add `Chooser` trait + `RandChooser<R: Rand>` blanket impl. Land in
   `libafl_bolts` or `libafl_core`. Zero behavior changes; pure addition.

2. Add `ChooserGenerator<I>` trait + `GenError`. Provide a blanket impl
   bridging `ChooserGenerator<I>` to `Generator<I, S>` via
   `state.rand_mut()`.

3. Add `ChoiceSeq` input + `ReplayChooser` + `SaverChooser`. Add the
   ChoiceSeq mutator family. Tests: replay-then-saver-equals-original.

4. Add `Guide` trait + `RandGuide`, `ReplayGuide`, `SaverGuide`. Add
   `GuidedGenStage` that loops on `make_chooser`. Tests: a deterministic
   generator + `ReplayGuide` + the converter reproduces a known
   testcase byte-for-byte.

5. Add `BfsGuide`, `EnumeratingGuide`, `WeightedSamplerGuide` as
   reference implementations. Each ships with a small example fuzzer
   under `fuzzers/generative/`.

6. Port one nontrivial demo: a tiny C-like expression generator wired
   into a `DiffExecutor` over two compilers, with a
   `DifferentialFeedback`. Goal: ~200 lines of user code.

7. (Optional, follow-up) `FilteringChooser` extension trait with
   `Filter`/`where` arguments, plus a `DfsBacktrackingGuide` that
   exploits filters.

Steps 1–4 are the load-bearing portion. They alone unlock the use case
and are upstream-ready in a single PR series.

## 8. Summary

LibAFL's compositional bones already accommodate generative blackbox
fuzzing — it's just that the one entity unique to that style (a
**chooser**, mediating generator-to-randomness) has no representation in
the framework. Adding `Chooser`, `ChooserGenerator`, `Guide`, and
`ChoiceSeq`, plus a `GuidedGenStage` that loops over them, makes every
other LibAFL entity slot into its existing role: `MutationalStage`
mutates choice sequences; existing executors run target bytes produced
by a `ToTargetBytesConverter`; existing feedbacks judge interestingness;
existing corpora and schedulers can be ignored or composed in. The
result is consistent with the paper's stated philosophy: orthogonal
techniques (BFS, weighted sampling, replay, mutation-of-tape) become
mix-and-match components rather than per-project reinventions.
