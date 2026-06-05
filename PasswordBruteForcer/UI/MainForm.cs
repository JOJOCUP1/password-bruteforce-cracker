using PasswordBruteForcer.Core;

namespace PasswordBruteForcer.UI;

/// <summary>
/// Task 2 &amp; Task 4f — The Windows Forms graphical interface.
///
/// It provides everything the brief asks for:
///   • password creation (random length [4,6) or a typed test password);
///   • a Start and a Stop button for the brute-force attack;
///   • a progress indicator (bar + counters) and an elapsed-time display;
///   • the found-password / result output area;
///   • a single-vs-multi performance comparison button (Task 8).
///
/// All long-running work happens on a background thread via Task.Run so the window stays
/// responsive; a forms Timer polls the engine's live counters and refreshes the display.
/// This file only deals with presentation and orchestration — every algorithm lives in Core/.
/// </summary>
public sealed class MainForm : Form
{
    private readonly PasswordHasher _hasher = new();
    private readonly char[] _charset = Program.Charset;
    private readonly System.Windows.Forms.Timer _uiTimer;

    private string? _targetHashHex;   // SHA-256 of the current target (what we crack against)
    private string? _secretPassword;  // the plain password (kept only to reveal/verify in the demo)
    private BruteForceEngine? _engine; // the engine currently running (polled by the timer)
    private CancellationTokenSource? _cts;

    // --- controls ---
    private Button _btnGenerate = null!, _btnUseCustom = null!, _btnStart = null!, _btnStop = null!, _btnCompare = null!;
    private TextBox _txtCustom = null!, _txtHash = null!, _txtLog = null!;
    private Label _lblSalt = null!, _lblSecret = null!, _lblThreads = null!,
                  _lblStatus = null!, _lblLength = null!, _lblAttempts = null!, _lblElapsed = null!, _lblSpeed = null!;
    private RadioButton _rbMulti = null!, _rbSingle = null!;
    private CheckBox _chkReveal = null!;
    private ProgressBar _progress = null!;

    public MainForm()
    {
        BuildUi();

        _uiTimer = new System.Windows.Forms.Timer { Interval = 100 };
        _uiTimer.Tick += (_, _) => UpdateProgressUi();

        _lblThreads.Text = $"Threads: {BruteForceEngine.RecommendedThreadCount}  (CPU cores − 1; {Environment.ProcessorCount} cores total)";
        AppendLog("Ready. Generate a random password (or type one), then press Start.");
        AppendLog($"Alphabet: a–z ({_charset.Length} symbols)   •   Max length searched: {Program.MaxLength}");
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //  Password creation (Task 2: "password creation")
    // ──────────────────────────────────────────────────────────────────────────────

    private void OnGenerateClick(object? sender, EventArgs e)
    {
        var generator = new PasswordGenerator(_charset);
        SetTargetPassword(generator.Generate(), random: true);
    }

    private void OnUseCustomClick(object? sender, EventArgs e)
    {
        string p = _txtCustom.Text.Trim().ToLowerInvariant();
        if (p.Length == 0 || p.Length > Program.MaxLength)
        {
            MessageBox.Show(this, $"Please type between 1 and {Program.MaxLength} characters.",
                "Invalid length", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        foreach (char c in p)
        {
            if (Array.IndexOf(_charset, c) < 0)
            {
                MessageBox.Show(this, "Only letters a–z are allowed — that is the alphabet the cracker searches.",
                    "Invalid character", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
        }
        SetTargetPassword(p, random: false);
    }

    private void SetTargetPassword(string password, bool random)
    {
        _secretPassword = password;
        _targetHashHex = _hasher.Hash(password);
        _txtHash.Text = _targetHashHex;
        UpdateRevealLabel();

        AppendLog("");
        AppendLog($"── New target password created ({(random ? "random" : "typed")}) ──");
        AppendLog($"  SHA-256(salt + password) = {_targetHashHex}");
        AppendLog($"  (the cracker is NOT told the length; it will start from length 1)");

        _progress.Value = 0;
        _lblStatus.Text = "Status: ready — press Start";
        _btnStart.Enabled = true;
        _btnCompare.Enabled = true;
    }

    private void UpdateRevealLabel()
    {
        if (_secretPassword is null) { _lblSecret.Text = "(no password yet)"; return; }
        _lblSecret.Text = _chkReveal.Checked ? _secretPassword : new string('•', _secretPassword.Length);
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //  Start / Stop the attack (Task 4f)
    // ──────────────────────────────────────────────────────────────────────────────

    private async void OnStartClick(object? sender, EventArgs e)
    {
        if (_targetHashHex is null)
            return;

        bool parallel = _rbMulti.Checked;
        PrepareForRun(parallel ? "multi-threaded attack" : "single-threaded attack");

        // Generator and validator are built independently (Task 7), then driven by the engine.
        var generator = new CombinationGenerator(_charset);
        var validator = new PasswordValidator(_targetHashHex, _hasher);
        _engine = new BruteForceEngine(generator, validator, 1, Program.MaxLength);
        _cts = new CancellationTokenSource();

        _uiTimer.Start();
        BruteForceResult result;
        try
        {
            result = await Task.Run(() => _engine.Run(parallel, _cts.Token));
        }
        finally
        {
            _uiTimer.Stop();
        }

        UpdateProgressUi();
        ShowResult(result);
        EndRun();
    }

    private void OnStopClick(object? sender, EventArgs e)
    {
        _cts?.Cancel(); // Task 6: triggers the shared token, every worker stops immediately
        _lblStatus.Text = "Status: stopping…";
        _btnStop.Enabled = false;
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //  Performance comparison: single-thread vs multi-thread (Task 8)
    // ──────────────────────────────────────────────────────────────────────────────

    private async void OnCompareClick(object? sender, EventArgs e)
    {
        if (_targetHashHex is null)
            return;

        PrepareForRun("performance comparison (single vs multi)");
        var generator = new CombinationGenerator(_charset);
        var validator = new PasswordValidator(_targetHashHex, _hasher);
        _cts = new CancellationTokenSource();
        var logger = new PerformanceLogger();

        _uiTimer.Start();
        try
        {
            AppendLog("[1/2] single-threaded run…");
            _engine = new BruteForceEngine(generator, validator, 1, Program.MaxLength, maxThreads: 1);
            var single = await Task.Run(() => _engine!.Run(parallel: false, _cts.Token));
            AppendLog($"      {single.Elapsed.TotalMilliseconds:F0} ms, {single.Attempts:N0} attempts");

            if (_cts.IsCancellationRequested)
            {
                AppendLog("Comparison cancelled.");
                return;
            }

            AppendLog("[2/2] multi-threaded run…");
            _engine = new BruteForceEngine(generator, validator, 1, Program.MaxLength);
            var multi = await Task.Run(() => _engine!.Run(parallel: true, _cts.Token));
            AppendLog($"      {multi.Elapsed.TotalMilliseconds:F0} ms, {multi.Attempts:N0} attempts, {multi.ThreadCount} threads");

            string comparison = logger.BuildComparison(single, multi, _secretPassword);
            logger.Append(comparison);
            AppendLog("");
            AppendLog(comparison);
            AppendLog($"(comparison appended to {logger.LogPath})");
        }
        finally
        {
            _uiTimer.Stop();
            UpdateProgressUi();
            EndRun();
        }
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //  UI helpers
    // ──────────────────────────────────────────────────────────────────────────────

    private void PrepareForRun(string what)
    {
        SetInputsEnabled(false);
        _btnStop.Enabled = true;
        _progress.Value = 0;
        AppendLog("");
        AppendLog($"=== Starting {what} ===");
        _lblStatus.Text = "Status: running…";
    }

    private void EndRun()
    {
        _cts?.Dispose();
        _cts = null;
        _engine = null;
        SetInputsEnabled(true);
        _btnStop.Enabled = false;
        _lblStatus.Text = "Status: idle — ready for another run";
    }

    private void SetInputsEnabled(bool enabled)
    {
        _btnGenerate.Enabled = enabled;
        _btnUseCustom.Enabled = enabled;
        _txtCustom.Enabled = enabled;
        _rbMulti.Enabled = enabled;
        _rbSingle.Enabled = enabled;
        _btnStart.Enabled = enabled && _targetHashHex != null;
        _btnCompare.Enabled = enabled && _targetHashHex != null;
    }

    private void UpdateProgressUi()
    {
        var engine = _engine;
        if (engine is null) return;

        int pct = (int)Math.Round(engine.CurrentLengthProgress * 100);
        _progress.Value = Math.Clamp(pct, 0, 100);
        _lblLength.Text = $"Current length: {engine.CurrentLength}";
        _lblAttempts.Text = $"Attempts: {engine.Attempts:N0}";
        _lblElapsed.Text = $"Elapsed: {Format(engine.Elapsed)}";
        double seconds = engine.Elapsed.TotalSeconds;
        _lblSpeed.Text = seconds > 0 ? $"Speed: {engine.Attempts / seconds:N0} hashes/s" : "Speed: —";
        if (engine.IsRunning)
            _lblStatus.Text = $"Status: searching length {engine.CurrentLength}…";
    }

    private void ShowResult(BruteForceResult r)
    {
        AppendLog("");
        AppendLog("──────────────── RESULT ────────────────");
        if (r.Found)
        {
            AppendLog($"✓ PASSWORD FOUND:  \"{r.Password}\"");
            bool verified = r.Password == _secretPassword;
            AppendLog($"  matches the secret password: {(verified ? "YES ✓" : "no")}");
        }
        else if (r.Cancelled)
        {
            AppendLog("■ STOPPED by user before the password was found.");
        }
        else
        {
            AppendLog("✗ password not found within the searched keyspace.");
        }

        AppendLog($"  mode      : {(r.Parallel ? "multi-threaded" : "single-threaded")}");
        AppendLog($"  threads   : {r.ThreadCount}");
        AppendLog($"  length    : {r.LengthReached}");
        AppendLog($"  attempts  : {r.Attempts:N0}");
        AppendLog($"  time      : {r.Elapsed.TotalMilliseconds:F0} ms  ({Format(r.Elapsed)})");
        AppendLog($"  speed     : {r.AttemptsPerSecond:N0} hashes/sec");

        if (r.Parallel && r.PerThreadAttempts.Count > 0)
        {
            AppendLog($"  parallel proof — {r.PerThreadAttempts.Count} threads each did work:");
            foreach (var kv in r.PerThreadAttempts.OrderByDescending(k => k.Value).Take(12))
                AppendLog($"      thread #{kv.Key,-4}: {kv.Value:N0} candidates");
        }
    }

    private void AppendLog(string text) => _txtLog.AppendText(text + Environment.NewLine);

    private static string Format(TimeSpan t) => t.ToString(@"mm\:ss\.fff");

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        _cts?.Cancel(); // make sure no background worker outlives the window
        base.OnFormClosing(e);
    }

    /// <summary>
    /// Drives the form SYNCHRONOUSLY into a representative state so a screenshot of the real UI can
    /// be rendered head-lessly with <see cref="Control.DrawToBitmap"/> (used by Program's
    /// <c>--capture</c> mode to produce the figures in the test report). This is a documentation
    /// helper only; the normal interactive flow uses the async Start/Compare handlers above.
    /// </summary>
    public void BuildDemoState(string mode)
    {
        CreateControl();
        PerformLayout();

        var passwordGenerator = new PasswordGenerator(_charset);
        SetTargetPassword(passwordGenerator.Generate(), random: true);

        if (mode == "ready")
        {
            _lblStatus.Text = "Status: ready — press Start";
            return;
        }

        var generator = new CombinationGenerator(_charset);
        var validator = new PasswordValidator(_targetHashHex!, _hasher);

        if (mode == "compare")
        {
            AppendLog("");
            AppendLog("=== Performance comparison (single vs multi) ===");
            var single = new BruteForceEngine(generator, validator, 1, Program.MaxLength, maxThreads: 1)
                .Run(parallel: false, CancellationToken.None);
            AppendLog($"[1/2] single-threaded: {single.Elapsed.TotalMilliseconds:F0} ms, {single.Attempts:N0} attempts");
            _engine = new BruteForceEngine(generator, validator, 1, Program.MaxLength);
            var multi = _engine.Run(parallel: true, CancellationToken.None);
            AppendLog($"[2/2] multi-threaded:  {multi.Elapsed.TotalMilliseconds:F0} ms, {multi.Attempts:N0} attempts, {multi.ThreadCount} threads");
            AppendLog("");
            AppendLog(new PerformanceLogger().BuildComparison(single, multi, _secretPassword));
            UpdateProgressUi();
            _progress.Value = 100;
            _lblStatus.Text = "Status: idle — comparison complete";
            return;
        }

        // mode == "found": run the multi-threaded attack to completion and show the result.
        AppendLog("");
        AppendLog("=== Multi-threaded attack ===");
        _engine = new BruteForceEngine(generator, validator, 1, Program.MaxLength);
        var result = _engine.Run(parallel: true, CancellationToken.None);
        UpdateProgressUi();
        _progress.Value = 100;
        ShowResult(result);
        _chkReveal.Checked = true;
        UpdateRevealLabel();
        _btnStop.Enabled = false;
        _lblStatus.Text = "Status: done — password found";
    }

    // ──────────────────────────────────────────────────────────────────────────────
    //  Layout — all controls are created in code (no designer file).
    // ──────────────────────────────────────────────────────────────────────────────

    private void BuildUi()
    {
        Text = "Password Brute-Force Cracker — Multithreaded Demo";
        Font = new Font("Segoe UI", 9f);
        ClientSize = new Size(820, 780);
        MinimumSize = new Size(700, 640);
        StartPosition = FormStartPosition.CenterScreen;

        AnchorStyles topAnchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

        // ---- 1. Password group ----
        var gbPassword = new GroupBox
        {
            Text = "1.  Password creation",
            Location = new Point(12, 12),
            Size = new Size(796, 184),
            Anchor = topAnchor
        };
        Controls.Add(gbPassword);

        _btnGenerate = new Button { Text = "🎲  Generate random password [4–6)", Location = new Point(16, 28), Size = new Size(270, 34) };
        _btnGenerate.Click += OnGenerateClick;

        var lblOr = new Label { Text = "or", Location = new Point(298, 36), AutoSize = true };

        _txtCustom = new TextBox { Location = new Point(326, 32), Size = new Size(150, 27) };
        _btnUseCustom = new Button { Text = "Use typed password", Location = new Point(486, 28), Size = new Size(180, 34) };
        _btnUseCustom.Click += OnUseCustomClick;

        var lblHashCaption = new Label { Text = "Target SHA-256 hash (hex):", Location = new Point(16, 74), AutoSize = true };
        _txtHash = new TextBox
        {
            Location = new Point(16, 96),
            Size = new Size(764, 27),
            ReadOnly = true,
            Font = new Font("Consolas", 9f),
            Anchor = topAnchor
        };

        var lblSaltCaption = new Label { Text = "Salt (constant):", Location = new Point(16, 132), AutoSize = true };
        _lblSalt = new Label { Text = PasswordHasher.Salt, Location = new Point(120, 132), AutoSize = true, Font = new Font("Consolas", 9f) };

        var lblRevealCaption = new Label { Text = "Reveal:", Location = new Point(430, 132), AutoSize = true };
        _chkReveal = new CheckBox { Location = new Point(488, 130), Size = new Size(20, 20) };
        _chkReveal.CheckedChanged += (_, _) => UpdateRevealLabel();
        _lblSecret = new Label { Text = "(no password yet)", Location = new Point(514, 132), AutoSize = true, Font = new Font("Consolas", 9f) };

        gbPassword.Controls.AddRange(new Control[]
        {
            _btnGenerate, lblOr, _txtCustom, _btnUseCustom,
            lblHashCaption, _txtHash, lblSaltCaption, _lblSalt, lblRevealCaption, _chkReveal, _lblSecret
        });

        // ---- 2. Attack group ----
        var gbAttack = new GroupBox
        {
            Text = "2.  Brute-force attack",
            Location = new Point(12, 204),
            Size = new Size(796, 100),
            Anchor = topAnchor
        };
        Controls.Add(gbAttack);

        var lblMode = new Label { Text = "Mode:", Location = new Point(16, 28), AutoSize = true };
        _rbMulti = new RadioButton { Text = "Multi-threaded (parallel)", Location = new Point(70, 26), Size = new Size(200, 24), Checked = true };
        _rbSingle = new RadioButton { Text = "Single-threaded", Location = new Point(280, 26), Size = new Size(140, 24) };
        _lblThreads = new Label { Text = "Threads: …", Location = new Point(440, 28), AutoSize = true };

        _btnStart = new Button { Text = "▶  Start", Location = new Point(16, 58), Size = new Size(150, 32), Enabled = false };
        _btnStart.Click += OnStartClick;
        _btnStop = new Button { Text = "■  Stop", Location = new Point(176, 58), Size = new Size(150, 32), Enabled = false };
        _btnStop.Click += OnStopClick;
        _btnCompare = new Button { Text = "⏱  Compare single vs multi", Location = new Point(336, 58), Size = new Size(230, 32), Enabled = false };
        _btnCompare.Click += OnCompareClick;

        gbAttack.Controls.AddRange(new Control[] { lblMode, _rbMulti, _rbSingle, _lblThreads, _btnStart, _btnStop, _btnCompare });

        // ---- 3. Progress group ----
        var gbProgress = new GroupBox
        {
            Text = "3.  Progress",
            Location = new Point(12, 312),
            Size = new Size(796, 130),
            Anchor = topAnchor
        };
        Controls.Add(gbProgress);

        _progress = new ProgressBar
        {
            Location = new Point(16, 28),
            Size = new Size(764, 26),
            Maximum = 100,
            Style = ProgressBarStyle.Continuous,
            Anchor = topAnchor
        };
        _lblStatus = new Label { Text = "Status: idle", Location = new Point(16, 62), AutoSize = true };
        _lblLength = new Label { Text = "Current length: —", Location = new Point(16, 88), AutoSize = true };
        _lblAttempts = new Label { Text = "Attempts: 0", Location = new Point(220, 88), AutoSize = true };
        _lblElapsed = new Label { Text = "Elapsed: 00:00.000", Location = new Point(16, 110), AutoSize = true };
        _lblSpeed = new Label { Text = "Speed: —", Location = new Point(220, 110), AutoSize = true };

        gbProgress.Controls.AddRange(new Control[] { _progress, _lblStatus, _lblLength, _lblAttempts, _lblElapsed, _lblSpeed });

        // ---- 4. Result / log group ----
        var gbResult = new GroupBox
        {
            Text = "4.  Result / log output",
            Location = new Point(12, 450),
            Size = new Size(796, 318),
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
        };
        Controls.Add(gbResult);

        _txtLog = new TextBox
        {
            Location = new Point(16, 26),
            Size = new Size(764, 280),
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Font = new Font("Consolas", 9f),
            BackColor = Color.FromArgb(24, 24, 24),
            ForeColor = Color.Gainsboro,
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
        };
        gbResult.Controls.Add(_txtLog);
    }
}
