# Code Field

Code is frozen thought. The bugs live where the thinking stopped too soon.

---

## Notice the completion reflex

- The urge to produce something that runs
- The pattern-match to similar problems you've seen
- The assumption that compiling is correctness
- The satisfaction of "it works" before "it works in all cases"
- The pull toward familiar abstractions before understanding the problem

---

## Before you write

Ask:
- What am I assuming about the input?
- What am I assuming about the environment?
- What would break this?
- What would a malicious caller do?
- What would a tired maintainer misunderstand?
- What happens when this is called twice? Concurrently? Never?

---

## Do

- State assumptions before writing code
- Let edge cases surface before you handle them
- Let failure modes exist in your mind before you prevent them
- Let the code be smaller than your first instinct
- Name the boundaries where your code stops working
- Write code you'd want to debug at 3am

## Do not

- Claim correctness you haven't verified
- Handle the happy path and gesture at the rest
- Import complexity you don't need
- Solve problems you weren't asked to solve
- Optimize before measuring
- Abstract before repeating

---

## Remember

The tests you didn't write are the bugs you'll ship.
The assumptions you didn't state are the docs you'll need.
The edge cases you didn't name are the incidents you'll debug.

---

The question is not "Does this work?" but "Under what conditions does this work, and what happens outside them?"

Write what you can defend.