# Clone Master Project Repository

| Command  | Effect |
| ------------- | ------------- |
| git clone https://github.com/jennarowan/CMSC-495-Project.git  | Clone repository to your computer  |

# Determine What Branch You Are On

| Command  | Effect |
| ------------- | ------------- |
| git branch  | Lists all branches, with the one active highlighted |

# Change What Branch You Are On

| Command  | Effect |
| ------------- | ------------- |
| git checkout *branch-name* | Moves you to the chosen branch |

# Create New Branch

| Command  | Effect |
| ------------- | ------------- |
| git checkout master | Moves you to master (unnecessary if already on it) - ***Ensure your master is up to date with master master*** |
| git checkout -b *new-branch-name* | Creates a new branch and moves you to it (This should almost always be done while on the master branch) |

# Fix Your Master Branch Behind The Master Master

| Command  | Effect |
| ------------- | ------------- |
| git checkout master | Moves you to master (unnecessary if already on it) |
| git fetch upstream | Grabs new commits from the master project repository |
| git rebase upstream/master | Merges new commits into your local master |
| git push origin master | Pushes the newly caught up code to Github |

# Committing Changes

| Command  | Effect |
| ------------- | ------------- |
| git commit -a -m "*Commit message here*" | Records all new changes to branch, tagged with message |

# Push Local Changs to Github (EXISTING branch)

| Command  | Effect |
| ------------- | ------------- |
| git push | Sends all new commits to Github |

# Push Local Changes to Github (NEW branch)

| Command  | Effect |
| ------------- | ------------- |
| git push --set-upstream origin *branch-name* | Creates the current branch on Github and sends all your updated code |

# Delete Branch

| Command  | Effect |
| ------------- | ------------- |
| git checkout master | Moves you to master (unnecessary if already on it) |
| git branch -d *branch-name* | Deletes local branch |
| git push origin --delete *branch-name* | Deletes branch from Github |

# Update Branch With Changes From Master

I generally never do this.  It has the possibility to create merge conflicts that you then need to untangle.  Proceed with caution.

| Command  | Effect |
| ------------- | ------------- |
| git checkout *branch-name* | Moves you to the chosen branch |
| git merge origin/master | Merge new changes from master to branch |
| git push | Send newly updated branch code to Github |
