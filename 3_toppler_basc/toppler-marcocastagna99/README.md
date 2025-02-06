[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/-1ACAqBK)
# Game Hacking
Toppler is an open-source clone of the old videogame [Nebulus](https://en.wikipedia.org/wiki/Nebulus_(video_game)).

The goal of the game is to reach the target door of each of the 8 towers in currently 2 missions with this little green animal. This door is usually at the very top of the tower.

But finding the way by using elevators and walking trough a maze of doors and platforms is not the only problem you have to solve. There are a bunch of other creatures living on the tower that will hinder you to reach your target by pushing you over the edge of the platforms.

The only weapon of defence you have is to throw a little snowball. But most of the other creatures just don't care about this. So you must avoid them.

A little submarine brings you from one tower to the next. On this way you have the chance to get some bonus points by catching fish. All you have to do is to catch a fish in a bubble with your torpedo and then collect the fish.

## The program

We provide only the binary code, without any sources. We do know you can easily google for them, the game is open-source after all, but please avoid to do so: the goal of this assignment is making the acquaintance with reversing engineering tools and making *small* changes to binary programs.

Inside the file "toppler_basc.tar.xz", available on AulaWeb, you'll find two executables, `toppler32` and `toppler64`, and some data files, used by both executables. See the included README.md for setup instructions.

`toppler32` is a 32-bit ELF executable with complete debug-symbols.
This is not the typical reversing scenario, but this is also your first reversing assignment ;)

`toppler64`, on the other hand, is a 64-bit ELF executable without any symbols.

### Command-line parameters
- `-f` should starts the game in fullscreen mode (not recommended)
- `-s` makes the game silent. If you don't have a soundcard or for another reason get an "can't open audio" error try this option.

### Game options
- **Password**: this menu entry allows you to define a password. The password is used to restart a mission from a tower that is not the first. You get a password for every third tower while you are playing
- **Lives**: for the tough guys you can decrease the number of lives you start the game
- **Status on top**: if you prefer the game status at the bottom of the screen. Here is the place to switch
- **Game speed**: if you want faster gameplay, then this is the option for you. This option doesn't influence the behaviour. Only the delays between the frames is decreased, so the game will run faster.

Toppler saves its configuration in `~/.toppler/.toppler.rc`

### Controls
In the menu you can select the mission you want to play next with the left and right cursor keys.  Press space or return on the start menu item to start the game.

The animal is controlled by the cursor keys and space (or return). Left and Right make the animal walk. Up and down make the elevators move if you are on one. (The elevator platforms are a little bit smaller than the normal platforms.)  If you are in front of a door press up to enter it.  Pressing the space key will either throw a snowball if you are standing still or make the animal jump if you are walking.

## Your BASC assignment

We ask you to find ways to cheat at the game, for instance, by: getting infinite lives, starting with more than three lives, freezing time, playing without robots or robot collisions, ...

### Part One: toppler32

Students with 9-CFU/6-CFU BASC should find (at least) four/two hacks, respectively. To get you started, our suggestion is to start analyzing the program functions using [Ghidra](https://ghidra-sre.org/) decompiler.

For each hack, you must:
- describe how you analyzed the binary and found the specific fragment of code (that is, which tools you used and how)
- provide a Python script that, starting from the provided file `toppler32`, produces a new "hacked" executable, with the corresponding cheat activated (please do not overwrite the original executable)

### Part Two: toppler64

Your task is the same of part one, but, this time, you need to work on the stripped 64-bit executable. Since you have no symbols, we give you some hints that will be way more helpful after you completed part one (note that we produced `toppler64` by compiling the same sources).

Hints (to see a particular address, you can use "Navigation -> Go To..." in Ghidra):
- the current number of lives is stored at address `0x42b8f0`
- function `akt_time` is at address `0x4063b2`
- some other interesting addresses are: `0x403e06`, `0x414d9e` and `0x414a44`

As in part one, students with 9-CFU/6-CFU BASC should find (at least) four/two hacks, respectively. For each hack, we expect an explanation and a Python script that, starting from `toppler64`, produces a new "hacked" executable with the corresponding hack enabled (the hacks for the 64-bit version can be the same that you found for the 32-bit version; but they must, of course, work on the 64-bit executable).

**Note: your scripts must work on our exact version of toppler32 and toppler64 (not on ones obtained by recompiling the sources).**
