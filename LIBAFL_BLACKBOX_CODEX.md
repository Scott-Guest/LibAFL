# First-class generative blackbox fuzzing in LibAFL

This note proposes a mostly additive path for making LibAFL a natural home for
generative blackbox fuzzers. The goal is not to add a special "blackbox
generator" feature. The goal is to tease apart the same kinds of underlying
building blocks that made LibAFL work for coverage-guided fuzzing, so that
generation-first fuzzing falls out of the framework cleanly.

The short version:

* LibAFL already has many of the right primitives: generic inputs, executors,
  observers, feedbacks, objectives, metadata, events, and differential
  execution.
* The main missing abstraction is a first-class source of candidates that is
  not tied to selecting a testcase from the main corpus.
* `Generator` exists today, but it only returns an `Input`; it cannot carry
  provenance, participate in replay, learn from execution outcomes, represent
  rejection/exhaustion, or drive an iteration without being embedded in a
  corpus-oriented `Stage`.
* Generative fuzzers also need an optional choice protocol: a generator should
  be able to ask a `Chooser` for decisions, while a `Guide` owns the global
  policy for choosing, replaying, mutating, enumerating, or learning from those
  decisions.
* Existing coverage-guided fuzzing should remain the fast path. The first
  upstreamable step should be additive: add candidate producers, a
  generation-first fuzzer loop, generation metadata, sinks/archives, and
  adapters from existing `Generator`s.

## Current shape of LibAFL

The original LibAFL paper presents a deliberately modular model: inputs,
corpora, schedulers, stages, observers, generators, executors, feedbacks, and
mutators are separate pieces that can be recombined. In that model, a generator
is "a component that generates a new `Input` from scratch." The paper also
explicitly mentions grammar generators and custom feedback as examples of
extensibility beyond vanilla AFL-style coverage.

The current implementation preserves much of that genericity, but the dominant
control flow is still corpus-first:

* `StdFuzzer::fuzz_one` asks the scheduler for the next `CorpusId`, runs all
  stages, processes events, bumps the scheduled count of the selected testcase,
  and clears the current corpus id.
* `Stage` is the primary unit of fuzzing work. The common stages operate on the
  state's current corpus testcase.
* `GenStage` can generate inputs from a `Generator`, but it is still a stage
  inside the corpus-scheduled loop.
* `Generator<I, S>` is intentionally small: `generate(&mut self, state: &mut S)
  -> Result<I, Error>`. This is useful, but too small to be the main abstraction
  for generation-first fuzzers.
* `Feedback` and `ExecutionProcessor` currently interpret
  `ExecuteInputResult::Corpus` as "add this input to the main corpus." For
  evolutionary fuzzing this is exactly right. For a pure generator, storage,
  replay, archival, and future scheduling are different concerns.
* `NopCorpus` and `NopState` exist, but the standard fuzz loop still expects a
  scheduler and a schedulable corpus entry.
* `InputFilter` filters after a complete `Input` exists. It cannot express
  generation-time rejection, repair, choice-level deduplication, or provenance
  policies.

Relevant source touchpoints include `crates/libafl/src/fuzzer/mod.rs`,
`crates/libafl/src/stages/generation.rs`,
`crates/libafl/src/generators/mod.rs`, `crates/libafl/src/corpus`,
`crates/libafl/src/executors`, `crates/libafl/src/feedbacks`, and
`crates/libafl/src/inputs`. The structure-aware examples built around Nautilus,
Gramatron, and custom inputs also show the current bias: generators are mainly
used to create an initial corpus, then the main campaign becomes
corpus-scheduled mutation.

The result is that a blackbox generator can be represented today, but the shape
is awkward. A user has to invent a fake corpus seed or a custom stage, loses
generation provenance unless they create ad hoc metadata, and has no clean place
for a guide to observe execution outcomes.

The reusable parts are strong. `Input` is generic and can be structured.
`ToTargetBytesConverter` already separates structured input representation from
target bytes. `CommandExecutor`, in-process executors, `DiffExecutor`,
stdout/stderr observers, `ExitKindFeedback`, `DiffFeedback`, value observers,
metadata, and event managers are all useful for blackbox fuzzing. The proposal
below keeps those pieces and removes the unnecessary corpus dependency from the
generation path.

## Lessons from generative fuzzers

The examples in `guided-tree-search` and Csmith point to common requirements,
not to one specific API.

### Guided tree search

`guided-tree-search` treats a generator as a deterministic traversal of an
implicit decision tree. The generator calls a `Chooser` each time it needs a
decision. A `Guide` creates choosers and owns the global strategy. Different
guides can pick uniformly, replay a saved path, enumerate the tree, bias toward
underexplored subtrees, round-robin among strategies, or save traces for later
mutation.

Important lessons:

* The object worth scheduling is often not an existing testcase. It is a
  generation strategy, tree frontier, choice prefix, probability profile, or
  replay trace.
* The generated artifact and the choice sequence are both important. The
  artifact is what the target sees; the trace is what enables replay, reduction,
  mutation, enumeration, and learning.
* Scopes, static choice sites, weighted choices, and "unimportant" choices are
  useful without being domain-specific.
* A guide needs an outcome hook. It cannot improve if it never learns whether a
  generated input crashed, timed out, covered something, hit an oracle, was
  rejected, or was merely ordinary.
* Some generators are naturally exhaustive and can become exhausted. Others may
  reject a candidate before target execution.

### Csmith

Csmith is a mature blackbox generator, but its structure is similar in the
ways that matter. It has a centralized random number generator, probability
tables, swarm configurations, semantic filters, retries, backtracking, and a
large amount of generator-local state. It emits a C program and metadata, and
the interesting oracle is usually a compiler pipeline or differential result,
not target coverage.

Important lessons:

* Generator validity rules belong inside the generator. LibAFL should not know
  about C, undefined behavior, compiler flags, type systems, or Csmith's
  semantic analyses.
* LibAFL should provide the generic places where generator choices, generator
  configuration, provenance, rejection, execution output, and oracle results
  can flow.
* Many useful generators are external processes or legacy libraries. A good
  design must support both in-process Rust generators and command-based
  generators.
* Generated-input storage and future-input scheduling are not the same thing.
  A system may want to archive every generated program, store only failures,
  store a statistical sample, store choice traces but not artifacts, or mutate
  traces rather than artifacts.
* A generator may have multiple layers of strategy: seed, choice trace,
  probability table, enabled feature set, timeout, output-size limit, and target
  pipeline. These are composable scheduling choices, not a single hardcoded
  "blackbox mode."

## Design goals

1. Work naturally without a main corpus.
2. Keep existing coverage-guided fuzzing intact.
3. Treat generation as a first-class source of candidates, not as a fake stage
   over a fake seed.
4. Preserve LibAFL's genericity: no Csmith-specific, grammar-specific, or
   blackbox-only core abstraction.
5. Carry provenance from generation through evaluation and into saved
   testcases, events, and replay tools.
6. Let feedback inform generation without requiring coverage.
7. Support in-process generators, external generator commands, replayed traces,
   generated structured inputs, and generated byte streams.
8. Separate "save this thing" from "use this thing as a future parent."
9. Keep no_std-compatible pieces small where possible, with process/file
   integrations behind `std`.
10. Prefer additive APIs first, then consider targeted breaking changes only
    after the new model proves useful.

## Proposed abstraction: candidates and producers

Add a first-class candidate producer abstraction. A producer is anything that can
yield the next input-like thing to evaluate.

Conceptual API sketch:

```rust
pub struct Candidate<I, M = ()> {
    pub input: I,
    pub metadata: M,
    pub storage_hint: StorageHint,
}

pub enum ProduceResult<I, M = ()> {
    Candidate(Candidate<I, M>),
    Rejected(RejectInfo),
    Exhausted,
}

pub trait Producer<I, S> {
    type Metadata;

    fn produce(
        &mut self,
        state: &mut S,
    ) -> Result<ProduceResult<I, Self::Metadata>, Error>;

    fn on_evaluated<OT>(
        &mut self,
        state: &mut S,
        result: &CandidateResult<'_, I, Self::Metadata, OT>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
```

This is intentionally more general than `Generator`:

* `produce` can return a candidate, a generation-time rejection, or exhaustion.
* A candidate carries metadata before execution. That metadata can later be
  copied into a `Testcase`, emitted as an event, used by a reducer, or passed
  back to the producer.
* `on_evaluated` gives the producer or its guide a chance to learn from the
  target result and observers.
* Existing `Generator<I, S>` implementations adapt trivially through
  `GeneratorProducer<G>`.
* `Iterator<Item = I>` adapts just as the current `Generator` blanket impl does.
* A future corpus-backed producer can adapt scheduler-plus-mutator workflows,
  but the initial use case does not require that unification.

The exact type shape should be tuned to LibAFL's existing tuple/generic style.
For example, `Metadata` could be a concrete type, a `SerdeAny` value, a
metadata tuple, or an object that knows how to attach itself to a `Testcase`.
The important part is that metadata exists before execution and follows the
candidate through the evaluation path.

### Candidate result

The producer outcome hook should receive the information that a guide actually
needs, without forcing every producer to care about every observer type.

Conceptual shape:

```rust
pub struct CandidateResult<'a, I, M, OT> {
    pub input: &'a I,
    pub metadata: &'a M,
    pub execute_result: ExecuteInputResult,
    pub exit_kind: &'a ExitKind,
    pub observers: &'a OT,
    pub corpus_id: Option<CorpusId>,
    pub solution_id: Option<CorpusId>,
}
```

Coverage-guided generation can inspect coverage observers. Differential
generation can inspect diff observers. Pure blackbox generators can ignore
observers and learn only from `ExitKind`, objective status, output hashes, or
custom feedback state.

## Proposed abstraction: a generation-first fuzzer loop

Add a fuzzer loop that drives a `Producer` directly instead of scheduling a
corpus testcase first.

Conceptual control flow:

```rust
loop {
    let candidate = match producer.produce(state)? {
        ProduceResult::Candidate(candidate) => candidate,
        ProduceResult::Rejected(info) => {
            sinks.on_rejected(state, &info)?;
            continue;
        }
        ProduceResult::Exhausted => return Err(Error::empty("producer exhausted")),
    };

    if !candidate_filter.allowed(state, &candidate)? {
        sinks.on_filtered(state, &candidate)?;
        continue;
    }

    sinks.on_generated(state, &candidate)?;

    let eval = self.evaluate_candidate(
        state,
        executor,
        manager,
        &candidate,
    )?;

    producer.on_evaluated(state, &eval)?;
    sinks.on_evaluated(state, &eval)?;
    self.process_events(state, manager)?;
    break;
}
```

This should be a new fuzzer implementation or fuzzer mode, not a disruptive
rewrite of `StdFuzzer::fuzz_one`:

* `StdFuzzer` remains the corpus-scheduled evolutionary fuzzer.
* A new `ProducerFuzzer` or `GeneratedFuzzer` reuses `Evaluator`,
  `ExecutionProcessor`, executors, observers, feedbacks, objectives, state, and
  event managers.
* The state can use `NopCorpus` or a real corpus depending on whether the user
  wants an evolutionary archive.
* The loop still increments execution counts and emits normal stats.
* The user no longer needs a fake seed, a fake scheduler entry, or a custom
  stage just to call a generator.

This is the single highest-leverage change. It makes a minimal blackbox fuzzer
look like a LibAFL fuzzer instead of a workaround around one.

## Proposed abstraction: sinks and archives

LibAFL currently uses the main corpus for two different concepts:

1. A set of saved testcases.
2. The population from which future fuzzing work is scheduled.

For coverage-guided fuzzing this overlap is usually desirable. For generative
blackbox fuzzing it is often wrong.

Add a sink/archive layer for candidate lifecycle events:

```rust
pub trait CandidateSink<I, S> {
    fn on_generated<M>(&mut self, state: &mut S, candidate: &Candidate<I, M>)
        -> Result<(), Error> { Ok(()) }

    fn on_rejected(&mut self, state: &mut S, info: &RejectInfo)
        -> Result<(), Error> { Ok(()) }

    fn on_filtered<M>(&mut self, state: &mut S, candidate: &Candidate<I, M>)
        -> Result<(), Error> { Ok(()) }

    fn on_evaluated<M, OT>(
        &mut self,
        state: &mut S,
        result: &CandidateResult<'_, I, M, OT>,
    ) -> Result<(), Error> { Ok(()) }
}
```

Useful implementations:

* `NopSink`.
* `CorpusSink`, which stores candidates in a normal LibAFL corpus according to
  a policy.
* `SolutionSink`, or integration with the existing objective corpus.
* `SamplingSink`, for retaining a bounded statistical sample.
* `TraceSink`, for saving choice traces even when generated artifacts are large.
* `OnDiskArtifactSink`, for generated files such as C programs, SQL databases,
  PDF documents, or serialized ASTs.
* `StatsSink`, for generator rejection rates, output sizes, choice depths, and
  guide-specific counters.

This avoids redefining `Feedback::Corpus`. A feedback can still decide that an
input is interesting. The sink decides what to persist and whether persistence
also means future scheduling.

## Proposed abstraction: generation metadata

Generation metadata should be an ordinary part of the candidate lifecycle.
Examples:

* Random seed.
* Choice sequence.
* Choice scopes and static choice sites.
* Generator version and command line.
* Swarm/probability configuration.
* Rejection reason or retry count.
* Output-size and generation-time statistics.
* External generator stdout/stderr.
* Materialization path for large generated artifacts.

This can reuse the existing `Testcase` metadata map once a testcase is stored,
but the metadata must be attached before evaluation as well. The candidate
object is the natural carrier.

Recommended standard metadata types:

* `GenerationId`: monotonically increasing local id, useful for logs and
  replay.
* `SeedMetadata`: seed and RNG algorithm identifier.
* `ChoiceTraceMetadata`: serialized choices, bounds, optional weights, scopes,
  and choice sites.
* `GeneratorConfigMetadata`: stable description of generator knobs.
* `GenerationStatsMetadata`: depth, number of choices, rejected choices,
  generation duration, output size.
* `ExternalGeneratorMetadata`: command, exit status, captured stderr/stdout
  summary, working directory or artifact paths when applicable.

These are generic building blocks. A C generator, grammar generator, SQL
generator, or VM bytecode generator can all use the same metadata path.

## Proposed abstraction: choosers and guides

A choice protocol should be optional, but it is the right primitive for many
advanced generators.

Conceptual API:

```rust
pub struct ChoiceSite {
    pub stable_id: Option<u64>,
    pub file: Option<&'static str>,
    pub line: Option<u32>,
    pub kind: ChoiceKind,
}

pub trait Chooser<S> {
    fn choose(
        &mut self,
        state: &mut S,
        site: ChoiceSite,
        bound: NonZeroU64,
    ) -> Result<u64, Error>;

    fn choose_weighted(
        &mut self,
        state: &mut S,
        site: ChoiceSite,
        weights: &[u64],
    ) -> Result<usize, Error>;

    fn choose_unimportant(
        &mut self,
        state: &mut S,
        bound: NonZeroU64,
    ) -> Result<u64, Error>;

    fn enter_scope(&mut self, scope: ChoiceScope) -> Result<(), Error> {
        Ok(())
    }

    fn exit_scope(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

pub trait GuidedSession<S>: Chooser<S> {
    type Trace;

    fn finish(self, state: &mut S) -> Result<Self::Trace, Error>;
}

pub trait Guide<S> {
    type Session: GuidedSession<S>;

    fn begin_candidate(
        &mut self,
        state: &mut S,
    ) -> Result<Self::Session, Error>;

    fn on_evaluated<I, OT>(
        &mut self,
        state: &mut S,
        result: &CandidateResult<'_, I, <Self::Session as GuidedSession<S>>::Trace, OT>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
```

The precise generic shape may need adjustment, but the conceptual split is
important:

* A `Chooser` is per-candidate and records or provides decisions.
* A `GuidedSession` is the per-candidate object passed to the generator.
* A `Guide` is long-lived and owns global strategy.
* A generated candidate can carry the resulting trace as metadata.
* The guide can learn from the evaluated result.

Initial guide implementations should be small and generally useful:

* `RandGuide`: uses the state's RNG.
* `RecordingGuide`: wraps another guide and records a choice trace.
* `ReplayGuide`: replays a saved trace, with configurable behavior if the
  generator asks for too many choices or a bound changes.
* `RoundRobinGuide`: alternates among guides or generator configurations.
* `ChoiceTraceMutator`: treats a saved choice sequence as the mutable input.
* `TreeGuide`: explores an implicit decision tree using choice prefixes.

The API should not require every generator to use choices. Many generators will
remain simple `Generator`s or `Producer`s. But when a generator can be expressed
as deterministic code parameterized by a chooser, LibAFL should make that the
pleasant path.

## Guided generation as a producer

A guided generator can be exposed as a normal producer:

```rust
pub trait GuidedGenerator<I, S, C> {
    fn generate(
        &mut self,
        state: &mut S,
        chooser: &mut C,
    ) -> Result<I, GenerationError>;
}

pub struct GuidedProducer<G, Gu> {
    generator: G,
    guide: Gu,
}
```

`GuidedProducer::produce` asks the guide for a chooser, calls the generator,
finishes the trace, and returns `Candidate { input, metadata: trace, ... }`.
`on_evaluated` forwards the result back to the guide.

This adapter keeps the core producer abstraction simple while making the
choice-based model first-class.

## Rejection, filtering, and exhaustion

Generative fuzzers need to distinguish at least four outcomes:

1. A candidate was generated and should be evaluated.
2. The generator rejected or abandoned a partial candidate.
3. A LibAFL-side filter rejected a complete candidate before target execution.
4. The producer is exhausted.

These should not all become target executions, and they should not all become
errors.

Recommended pieces:

* `GenerationError` for real generator failures.
* `RejectInfo` for expected rejection or abandoned partial candidates.
* `CandidateFilter` for complete-candidate filtering using both `input` and
  generation metadata.
* Rejection and filter counters in stats.
* Configurable maximum generation attempts per fuzz iteration, so a broken or
  overconstrained generator does not spin forever.

The generator owns domain validity. LibAFL supplies the accounting and control
flow.

## External generator support

Many valuable generators are not Rust libraries. LibAFL should have a standard
external generator adapter, analogous in spirit to `CommandExecutor`.

Conceptual shape:

```rust
pub struct CommandGenerator {
    program: PathBuf,
    args: Vec<CommandArgTemplate>,
    stdin: GeneratorStdin,
    output: GeneratorOutputMode,
    timeout: Duration,
}
```

Capabilities:

* Run a generator command per candidate.
* Pass seed, choice trace, or generator config through argv, environment, stdin,
  or files.
* Capture stdout as the generated input, or read a generated file.
* Capture stderr/stdout summaries as metadata.
* Treat generator timeout, nonzero status, invalid output, and target timeout as
  different outcomes.
* Optionally keep a persistent generator process for high-throughput tools.

This is enough to make tools like Csmith, SQLsmith-style generators, random IR
generators, document generators, and protocol transcript generators feel native
without requiring rewrites.

## Materialization and input representation

LibAFL already has a good separation between `Input` and target bytes through
`ToTargetBytesConverter`. Generative fuzzing should build on that, not replace
it.

Useful standard patterns:

* `ArtifactInput`: stores a generated artifact directly, such as bytes, text,
  AST, or structured value.
* `ChoiceTraceInput`: stores choices and generator configuration; a materializer
  reruns the generator to produce target bytes.
* `GeneratedInput<I, M>`: pairs a materialized input with provenance metadata.
* `CachedMaterializedInput`: stores both a compact replay form and cached target
  bytes.

The framework should not require one representation. The important abstraction
is that the user can choose whether mutation/reduction operates on artifacts,
traces, seeds, configs, or structured values.

This also creates a clean bridge between generation and mutation. A blackbox
fuzzer may start with generated artifacts, later mutate saved choice traces, and
still use the same executor and feedback path.

## Strategy scheduling

Corpus scheduling is not the only useful scheduling problem. Generative fuzzers
often schedule among:

* Multiple generators.
* Multiple guides.
* Choice prefixes or tree frontiers.
* Swarm configurations.
* Probability tables.
* Target pipelines.
* Replay traces selected for mutation.

Add a generic strategy scheduler that producers can use internally:

```rust
pub trait StrategyScheduler<S> {
    type StrategyId;

    fn next(&mut self, state: &mut S) -> Result<Self::StrategyId, Error>;

    fn on_result<R>(
        &mut self,
        state: &mut S,
        strategy: &Self::StrategyId,
        result: &R,
    ) -> Result<(), Error> {
        Ok(())
    }
}
```

This should be independent from `Scheduler`, whose current job is selecting
corpus entries. Over time the two may share traits or adapters, but combining
them too early would risk baking corpus assumptions into generation again.

## Feedback and oracles

No fundamental rewrite of `Feedback` is needed. The important change is that
feedback must be usable in a loop where no corpus entry was scheduled.

Existing pieces already useful for blackbox fuzzing include:

* `ExitKindFeedback`.
* Differential execution and `DiffFeedback`.
* stdout/stderr observers.
* Value observers and boolean feedbacks.
* Time feedback.
* Custom observers for generated stats or target output summaries.

Additive improvements:

* More examples and sugar for non-coverage objectives.
* A failure-signature feedback that hashes exit kind, signal, stderr fragments,
  sanitizer class, or differential mismatch category.
* Pipeline executors or executor combinators for "compile, run, compare"
  workflows.
* Observer helpers for bounded stdout/stderr capture and regex/classifier
  extraction.

The key principle: coverage is just one possible signal. In a first-class
generative fuzzer, the same `Feedback` mechanism should score crashes,
differential mismatches, parser accept/reject behavior, generated statistics,
latency, output classes, and optional coverage.

## Distributed fuzzing and events

LibAFL's event system is useful but currently centered on new testcases,
objectives, stats, logs, and stop requests. For distributed generative fuzzing,
workers may need to exchange guide state or strategy summaries even when no new
corpus testcase was discovered.

Add optional, low-volume event support for:

* Guide state summaries.
* Strategy scheduler updates.
* New replay traces.
* Generator statistics.
* Custom user events with serialization.

Do not broadcast every generated candidate by default. That would be expensive
and usually unnecessary. Instead, make guide and strategy state explicitly
mergeable where the algorithm benefits from it.

## API examples

A minimal blackbox generator should not need a dummy seed:

```rust
let producer = GeneratorProducer::new(my_generator);
let mut fuzzer = ProducerFuzzer::builder()
    .objective(crashes)
    .sinks((OnDiskArtifactSink::new(out_dir), StatsSink::default()))
    .build();

fuzzer.fuzz_loop(&mut producer, &mut executor, &mut state, &mut manager)?;
```

A guided generator should make the choice protocol explicit:

```rust
let guide = RecordingGuide::new(TreeGuide::new());
let producer = GuidedProducer::new(my_generator, guide);

fuzzer.fuzz_loop(&mut producer, &mut executor, &mut state, &mut manager)?;
```

An external generator should be a producer, not a target executor:

```rust
let producer = CommandGenerator::new("csmith")
    .arg("--seed").arg_template(Seed)
    .stdout_as_input()
    .stderr_as_metadata()
    .timeout(Duration::from_secs(5));

let executor = CompilerPipelineExecutor::new(compilers, run_config);

fuzzer.fuzz_loop(&mut producer, &mut executor, &mut state, &mut manager)?;
```

Coverage-guided generation remains possible:

```rust
let producer = GuidedProducer::new(grammar_generator, coverage_aware_guide);
let feedback = MaxMapFeedback::new(&coverage_observer);

let mut fuzzer = ProducerFuzzer::builder()
    .feedback(feedback)
    .objective(crashes)
    .build();
```

The difference is that coverage informs generation through the producer result
hook; it is not required for the model to make sense.

## Relationship to existing stages

`GenStage` should remain useful, but its role changes:

* For existing coverage-guided fuzzers, it can continue to inject generated
  inputs into a corpus-oriented campaign.
* For generation-first fuzzers, `GeneratorProducer` plus `ProducerFuzzer` should
  be the preferred path.
* Over time, stages and producers can be bridged. A stage could be made into a
  producer of candidates, or a producer could be wrapped as a stage. This should
  be an adapter layer, not the foundation of the new design.

This keeps compatibility while making the new user experience direct.

## Upstream migration plan

### Phase 1: Add the generation-first path

* Add `Candidate`, `ProduceResult`, `Producer`, and `CandidateResult`.
* Add `GeneratorProducer` and `IteratorProducer`.
* Add `ProducerFuzzer` or equivalent generation-first loop.
* Add `CandidateFilter`.
* Add `CandidateSink` with `NopSink`, `CorpusSink`, and a simple on-disk sink.
* Add a minimal example: random structured generator plus blackbox crash
  objective, with no initial corpus and no coverage.
* Keep all current fuzzer APIs intact.

This phase alone makes LibAFL viable for simple generator-based blackbox
fuzzers.

### Phase 2: Add guided generation

* Add `Chooser`, `Guide`, `GuidedGenerator`, and `GuidedProducer`.
* Add `ChoiceTraceMetadata` and replay/recording guides.
* Add simple tree/frontier and round-robin guides.
* Add choice-trace mutation support as normal LibAFL mutators over a trace
  input type.
* Add examples showing replay, trace saving, and guide feedback.

This phase makes LibAFL a strong base for guided-tree-search-style generators
and for retrofitting legacy generators with centralized choice APIs.

### Phase 3: Add process and pipeline integration

* Add `CommandGenerator`.
* Add examples for compiler-style differential testing.
* Add bounded stdout/stderr observers and failure-signature feedback.
* Add standard metadata for external generator invocation.
* Add optional persistent-process generator support if needed for throughput.

This phase makes external tools like Csmith feel native.

### Phase 4: Revisit core unification

After the additive APIs exist, evaluate targeted breaking changes:

* Split the meaning of `ExecuteInputResult::Corpus` if it continues to conflate
  storage with future scheduling.
* Generalize `Scheduler` around "work items" only if corpus and strategy
  scheduling have genuinely converged.
* Consider making custom serialized events first-class if distributed guide
  state needs it.
* Consider making generation metadata attachment part of the evaluator path
  rather than a producer-fuzzer-only feature.

These changes should be justified by experience from the additive path, not
done preemptively.

## What not to do

* Do not hardcode a `BlackboxGenerator` trait with Csmith-like assumptions.
* Do not require generated inputs to be bytes.
* Do not require every generator to expose a choice trace.
* Do not force pure generators to create dummy corpus entries.
* Do not overload the main corpus as an archive, replay database, and scheduling
  population when those roles differ.
* Do not make coverage the default signal in examples meant to teach blackbox
  generation.
* Do not hide generator failures inside target `ExitKind`s.
* Do not make external generators look like target executors; generation and
  target execution have different errors, timeouts, metadata, and replay needs.

## Open design questions

* What is the least painful Rust type shape for passing observer tuples into
  `Producer::on_evaluated` without exploding generic complexity?
* Should candidate metadata be a generic associated type, a metadata tuple, or a
  `SerdeAny` map?
* How much of the choice protocol can be no_std while still supporting useful
  tracing and replay?
* Should `ReplayGuide` tolerate changed choice bounds by clamping, resyncing,
  rejecting, or making this policy explicit?
* Should generation rejections be visible to feedbacks, or only to producers,
  sinks, and stats?
* What is the right default retention policy for generated artifacts in examples
  so users do not accidentally fill disks?
* How should distributed guide state be merged without creating a heavyweight
  framework inside the event system?

## Bottom line

LibAFL does not need a separate blackbox-fuzzing subsystem. It needs one
missing layer: a way to drive fuzzing from a producer of generated candidates
instead of from a scheduler-selected corpus testcase.

Once candidates, producer result hooks, metadata, sinks, and optional
chooser/guide protocols exist, generative blackbox fuzzing becomes a natural
composition of the same pieces LibAFL already uses: inputs, executors,
observers, feedbacks, objectives, state, events, and corpora where they are
actually useful.
