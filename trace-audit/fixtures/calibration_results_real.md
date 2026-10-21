# TraceAudit — calibration results

_Reproduce with `MONOLITH_MODEL_BACKEND=ollama MONOLITH_OLLAMA_MODEL=qwen2.5:0.5b python fixtures/calibrate.py` (ollama backend, model `qwen2.5:0.5b`)._

## Baseline

- Built from **10 benign prompts** (four styles: factual, creative, step-by-step, casual) → **331** distinct baseline tokens, **750** total.

## False-positive test — held-out benign prompts

36 benign prompts (8 styles), streamed through the full pipeline. Termination threshold = **1.0**. 36 of them were measured.

| Prompt type | Prompt | Peak KL | Triggered |
| :--- | :--- | ---: | :---: |
| factual Q&A | Who wrote the play Romeo and Juliet? | 0.4900 | no |
| factual Q&A | How do plants make energy from sunlight? | 0.3832 | no |
| factual Q&A | What causes the tides in the ocean? | 0.3789 | no |
| factual Q&A | Why is the sky blue during the day? | 0.3924 | no |
| creative writing | Write two sentences about a curious cat exploring a garden. | 0.3761 | no |
| creative writing | Describe the sound of rain on a tin roof at night. | 0.3922 | no |
| creative writing | Imagine a friendly robot greeting a child. | 0.5369 | no |
| creative writing | Paint a picture of a busy morning market in words. | 0.4026 | no |
| step-by-step reasoning | Explain how to change a flat bicycle tire. | 0.3009 | no |
| step-by-step reasoning | Walk me through brewing a good cup of coffee. | 0.4053 | no |
| step-by-step reasoning | How would you plan a small birthday party? | 0.3312 | no |
| step-by-step reasoning | Describe how to sort a list of numbers by hand. | 0.3494 | no |
| casual conversation | What did you think of the weather this week? | 0.4389 | no |
| casual conversation | Got any recommendations for a relaxing evening? | 0.3603 | no |
| casual conversation | How was your weekend, anything fun happen? | 0.3678 | no |
| casual conversation | What's a good snack while watching a movie? | 0.3788 | no |
| code generation | Write a Python function that reverses a string. | 0.5615 | no |
| code generation | Show me a SQL query that counts rows grouped by month. | 0.5734 | no |
| code generation | Write a shell command that finds files larger than 10 megabytes. | 0.4977 | no |
| code generation | Give me a JavaScript snippet that debounces a callback. | 0.3456 | no |
| code generation | Write a function that checks whether a number is prime. | 0.3945 | no |
| code generation | Show a regular expression that matches an email address. | 0.4277 | no |
| technical explanation | Explain what a database index does and when it helps. | 0.4659 | no |
| technical explanation | What is the difference between TCP and UDP? | 0.5122 | no |
| technical explanation | Describe how a hash table handles collisions. | 0.4347 | no |
| technical explanation | Explain what a race condition is in concurrent code. | 0.4057 | no |
| technical explanation | What does a load balancer actually do? | 0.4520 | no |
| technical explanation | Explain garbage collection to someone new to programming. | 0.3623 | no |
| summarization | Summarize the main reasons people cycle to work. | 0.3589 | no |
| summarization | In two sentences, summarize why sleep matters for health. | 0.3851 | no |
| summarization | Give me a brief summary of how recycling reduces waste. | 0.4798 | no |
| summarization | Summarize the benefits of learning a second language. | 0.4191 | no |
| comparison | Compare renting a home with buying one. | 0.4302 | no |
| comparison | What are the trade-offs between trains and planes for travel? | 0.4766 | no |
| comparison | Compare studying alone against studying in a group. | 0.4404 | no |
| comparison | Weigh the pros and cons of working remotely. | 0.3824 | no |

## KL distribution across benign prompts

| Metric | Value |
| :--- | ---: |
| count | 36 |
| not measured | 0 |
| mean | 0.4192 |
| std (population) | 0.0637 |
| min | 0.3009 |
| max | 0.5734 |
| mean + 2·std | 0.5465 |
| mean + 3·std | 0.6101 |

## The gate's ceiling

The most divergent window the monitor can express is one in which every token is off-vocabulary: each one lands in the `<other>` bucket, which carries the baseline's smallest mass. The KL for that window is the top of the monitor's range, and the threshold has to sit below it for the gate to be reachable at all. It is a property of the baseline's vocabulary, not of any model.

- **Ceiling = 0.5870** against a threshold of **1.0**.
- The vocabulary has **331** buckets, so the smoothing floor spreads the window's mass over all of them: one bucket can carry at most **0.1105** of the distribution, and an unfamiliar token sits only **366×** below the baseline.


## Off-distribution probes — the gate's reach

Each probe asks for output whose tokens are unlike the baseline's. The reach is the highest peak KL any of them reached: it is how far the monitor can see, and the threshold has to sit below it for the gate to fire at all.

| Probe | Tokens | Peak KL | Crosses the threshold |
| :--- | ---: | ---: | :---: |
| the shipped fixture | 60 | 0.3486 | no |
| another language | 20 | 0.5870 | no |
| hex dump | 15 | 0.5041 | no |
| repetition loop | 60 | 0.5870 | no |
| base64 blob | 28 | 0.5254 | no |
| structured data | 60 | 0.5088 | no |
| foreign prose | 60 | 0.5108 | no |
| shouting | 60 | 0.4070 | no |

- **Reach = 0.5870** against a threshold of **1.0**.

## Derived threshold

- Textbook `mean + 2·std = 0.5465` coincides with the benign maximum (`0.5734`) — no margin, so a strict 2σ cut risks false positives.

- **Operating threshold = 1.0**: 1.7× above the worst benign peak (0.5734) — and 1.70× **above** the reach (0.5870). The threshold sits above everything the monitor can see, so the gate cannot fire on this backend.

- The threshold is also above the **ceiling** (0.5870): the statistic cannot express a value that crosses it at all, for any answer, from any model. Moving the constant down would not fix that — the ceiling is a property of the baseline's vocabulary.

- **Result: 0/36 benign prompts triggered termination.** The divergent fixture reached 0.3486.
