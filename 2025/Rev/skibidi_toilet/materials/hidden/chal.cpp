#include <bits/stdc++.h>

using namespace std;
using u64 = unsigned long long;

u64 choose_next(const set<u64> &occupied, const vector<u64> &occ_list, u64 N) {
  u64 best_pos = 0;
  u64 best_dist = 0;
  for (u64 pos = 1; pos <= N; ++pos) {
    if (occupied.count(pos))
      continue;
    u64 min_d = ULLONG_MAX;
    for (u64 occ : occ_list) {
      u64 d = pos > occ ? pos - occ : occ - pos;
      if (d < min_d)
        min_d = d;
    }
    if (min_d > best_dist) {
      best_dist = min_d;
      best_pos = pos;
    }
  }
  return best_pos;
}

u64 simulate_bruteforce(u64 k, u64 N) {
  if (k == 1)
    return 1;
  set<u64> occupied;
  vector<u64> occ_list;

  occupied.insert(1);
  occ_list.push_back(1);
  if (k == 1)
    return 1;

  occupied.insert(N);
  occ_list.push_back(N);
  if (k == 2)
    return N;

  u64 chosen = 0;
  for (u64 i = 3; i <= k; ++i) {
    chosen = choose_next(occupied, occ_list, N);
    occupied.insert(chosen);
    occ_list.push_back(chosen);
  }
  return chosen;
}

string bits_to_art(u64 p, unsigned bits) {
  string s(bits, ' ');
  for (int i = bits - 1; i >= 0; --i) {
    if ((p >> i) & 1ULL) {
      s[bits - 1 - i] = '#';
    }
  }
  return s;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    cerr << "Usage: " << argv[0] << " input.txt\n";
    return 1;
  }

  ifstream infile(argv[1]);
  if (!infile) {
    perror("open input");
    return 1;
  }

  unsigned bits;
  if (!(infile >> bits)) {
    cerr << "Error: could not read brush size\n";
    return 1;
  }
  if (bits == 0 || bits > 60) {
    cerr << "Error: brush size must be between 1 and 60\n";
    return 1;
  }
  u64 N = (1ULL << bits) - 1;

  string line;
  getline(infile, line);

  while (getline(infile, line)) {
    if (line.empty()) {
      cout << "\n";
      continue;
    }

    stringstream ss(line);
    u64 k;

    while (ss >> k) {
      if (k > N) {
        cerr << "Error: k = " << k << " is too large\n";
        return 1;
      }

      u64 pos = simulate_bruteforce(k, N);
      cout << bits_to_art(pos, bits);
    }
    cout << "\n";
  }

  return 0;
}
