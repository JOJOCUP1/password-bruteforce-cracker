using PasswordBruteForcer.Core;

namespace PasswordBruteForcer.UI;

public sealed class MainForm : Form
{
    private readonly PasswordHasher _hasher = new();
    private readonly char[] _charset = Program.Charset;
    private readonly System.Windows.Forms.Timer _uiTimer;

    private string? _targetHashHex;
    private string? _secretPassword;
    private BruteForceEngine? _engine;
    private CancellationTokenSource? _cts;

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
        _lblThreads.Text = $"Threads: {BruteForceEngine.RecommendedThreadCount}  (CPU cores - 1; {Environment.ProcessorCount} cores total)";
        AppendLog("Ready. Generate a random password (or type one), then press Start.");
        AppendLog($"Alphabet: a-z ({_charset.Length} symbols)   |   Max length searched: {Program.MaxLength}");
    }

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
                MessageBox.Show(this, "Only letters a-z are allowed.",
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
        AppendLog($"-- New target password ({(random ? "random" : "typed")}) --");
        AppendLog($"  SHA-256(salt + password) = {_targetHashHex}");
        AppendLog($"  (brute force starts from length 1)");

        _progress.Value = 0;
        _lblStatus.Text = "Status: ready";
        _btnStart.Enabled = true;
        _btnCompare.Enabled = true;
    }

    private void UpdateRevealLabel()
    {
        if (_secretPassword is null) { _lblSecret.Text = "(no password yet)"; return; }
        _lblSecret.Text = _chkReveal.Checked ? _secretPassword : new string('*', _secretPassword.Length);
    }

    private async void OnStartClick(object? sender, EventArgs e)
    {
        if (_targetHashHex is null) return;

        bool parallel = _rbMulti.Checked;
        PrepareForRun(parallel ? "multi-threaded attack" : "single-threaded attack");

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
        _cts?.Cancel();
        _lblStatus.Text = "Status: stopping...";
        _btnStop.Enabled = false;
    }

    private async void OnCompareClick(object? sender, EventArgs e)
    {
        if (_targetHashHex is null) return;

        PrepareForRun("performance comparison (single vs multi)");
        var generator = new CombinationGenerator(_charset);
        var validator = new PasswordValidator(_targetHashHex, _hasher);
        _cts = new CancellationTokenSource();
        var logger = new PerformanceLogger();

        _uiTimer.Start();
        try
        {
            AppendLog("[1/2] single-threaded run...");
            _engine = new BruteForceEngine(generator, validator, 1, Program.MaxLength, maxThreads: 1);
            var single = await Task.Run(() => _engine!.Run(parallel: false, _cts.Token));
            AppendLog($"      {single.Elapsed.TotalMilliseconds:F0} ms, {single.Attempts:N0} attempts");

            if (_cts.IsCancellationRequested) { AppendLog("Cancelled."); return; }

            AppendLog("[2/2] multi-threaded run...");
            _engine = new BruteForceEngine(generator, validator, 1, Program.MaxLength);
            var multi = await Task.Run(() => _engine!.Run(parallel: true, _cts.Token));
            AppendLog($"      {multi.Elapsed.TotalMilliseconds:F0} ms, {multi.Attempts:N0} attempts, {multi.ThreadCount} threads");

            string comparison = logger.BuildComparison(single, multi, _secretPassword);
            logger.Append(comparison);
            AppendLog("");
            AppendLog(comparison);
            AppendLog($"(saved to {logger.LogPath})");
        }
        finally
        {
            _uiTimer.Stop();
            UpdateProgressUi();
            EndRun();
        }
    }

    private void PrepareForRun(string what)
    {
        SetInputsEnabled(false);
        _btnStop.Enabled = true;
        _progress.Value = 0;
        AppendLog("");
        AppendLog($"=== Starting {what} ===");
        _lblStatus.Text = "Status: running...";
    }

    private void EndRun()
    {
        _cts?.Dispose();
        _cts = null;
        _engine = null;
        SetInputsEnabled(true);
        _btnStop.Enabled = false;
        _lblStatus.Text = "Status: idle";
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
        _lblSpeed.Text = seconds > 0 ? $"Speed: {engine.Attempts / seconds:N0} hashes/s" : "Speed: -";
        if (engine.IsRunning)
            _lblStatus.Text = $"Status: searching length {engine.CurrentLength}...";
    }

    private void ShowResult(BruteForceResult r)
    {
        AppendLog("");
        AppendLog("-------- RESULT --------");
        if (r.Found)
        {
            AppendLog($"PASSWORD FOUND: \"{r.Password}\"");
            AppendLog($"  matches secret: {(r.Password == _secretPassword ? "YES" : "NO")}");
        }
        else if (r.Cancelled)
            AppendLog("Stopped by user.");
        else
            AppendLog("Password not found.");

        AppendLog($"  mode     : {(r.Parallel ? "multi-threaded" : "single-threaded")}");
        AppendLog($"  threads  : {r.ThreadCount}");
        AppendLog($"  attempts : {r.Attempts:N0}");
        AppendLog($"  time     : {r.Elapsed.TotalMilliseconds:F0} ms");
        AppendLog($"  speed    : {r.AttemptsPerSecond:N0} hashes/sec");

        if (r.Parallel && r.PerThreadAttempts.Count > 0)
        {
            AppendLog($"  threads that did work: {r.PerThreadAttempts.Count}");
            foreach (var kv in r.PerThreadAttempts.OrderByDescending(k => k.Value).Take(12))
                AppendLog($"    thread #{kv.Key,-4}: {kv.Value:N0} candidates");
        }
    }

    private void AppendLog(string text) => _txtLog.AppendText(text + Environment.NewLine);
    private static string Format(TimeSpan t) => t.ToString(@"mm\:ss\.fff");

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        _cts?.Cancel();
        base.OnFormClosing(e);
    }

    private void BuildUi()
    {
        Text = "Password Brute-Force Cracker";
        Font = new Font("Segoe UI", 9f);
        ClientSize = new Size(820, 780);
        MinimumSize = new Size(700, 640);
        StartPosition = FormStartPosition.CenterScreen;

        AnchorStyles topAnchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;

        var gbPassword = new GroupBox { Text = "1. Password creation", Location = new Point(12, 12), Size = new Size(796, 184), Anchor = topAnchor };
        Controls.Add(gbPassword);

        _btnGenerate = new Button { Text = "Generate random password [4-6)", Location = new Point(16, 28), Size = new Size(270, 34) };
        _btnGenerate.Click += OnGenerateClick;

        var lblOr = new Label { Text = "or", Location = new Point(298, 36), AutoSize = true };
        _txtCustom = new TextBox { Location = new Point(326, 32), Size = new Size(150, 27) };
        _btnUseCustom = new Button { Text = "Use typed password", Location = new Point(486, 28), Size = new Size(180, 34) };
        _btnUseCustom.Click += OnUseCustomClick;

        var lblHashCaption = new Label { Text = "Target SHA-256 hash:", Location = new Point(16, 74), AutoSize = true };
        _txtHash = new TextBox { Location = new Point(16, 96), Size = new Size(764, 27), ReadOnly = true, Font = new Font("Consolas", 9f), Anchor = topAnchor };

        var lblSaltCaption = new Label { Text = "Salt:", Location = new Point(16, 132), AutoSize = true };
        _lblSalt = new Label { Text = PasswordHasher.Salt, Location = new Point(52, 132), AutoSize = true, Font = new Font("Consolas", 9f) };

        var lblRevealCaption = new Label { Text = "Reveal:", Location = new Point(430, 132), AutoSize = true };
        _chkReveal = new CheckBox { Location = new Point(488, 130), Size = new Size(20, 20) };
        _chkReveal.CheckedChanged += (_, _) => UpdateRevealLabel();
        _lblSecret = new Label { Text = "(no password yet)", Location = new Point(514, 132), AutoSize = true, Font = new Font("Consolas", 9f) };

        gbPassword.Controls.AddRange(new Control[] { _btnGenerate, lblOr, _txtCustom, _btnUseCustom, lblHashCaption, _txtHash, lblSaltCaption, _lblSalt, lblRevealCaption, _chkReveal, _lblSecret });

        var gbAttack = new GroupBox { Text = "2. Brute-force attack", Location = new Point(12, 204), Size = new Size(796, 100), Anchor = topAnchor };
        Controls.Add(gbAttack);

        var lblMode = new Label { Text = "Mode:", Location = new Point(16, 28), AutoSize = true };
        _rbMulti = new RadioButton { Text = "Multi-threaded (parallel)", Location = new Point(70, 26), Size = new Size(200, 24), Checked = true };
        _rbSingle = new RadioButton { Text = "Single-threaded", Location = new Point(280, 26), Size = new Size(140, 24) };
        _lblThreads = new Label { Text = "Threads: ...", Location = new Point(440, 28), AutoSize = true };

        _btnStart = new Button { Text = "Start", Location = new Point(16, 58), Size = new Size(150, 32), Enabled = false };
        _btnStart.Click += OnStartClick;
        _btnStop = new Button { Text = "Stop", Location = new Point(176, 58), Size = new Size(150, 32), Enabled = false };
        _btnStop.Click += OnStopClick;
        _btnCompare = new Button { Text = "Compare single vs multi", Location = new Point(336, 58), Size = new Size(230, 32), Enabled = false };
        _btnCompare.Click += OnCompareClick;

        gbAttack.Controls.AddRange(new Control[] { lblMode, _rbMulti, _rbSingle, _lblThreads, _btnStart, _btnStop, _btnCompare });

        var gbProgress = new GroupBox { Text = "3. Progress", Location = new Point(12, 312), Size = new Size(796, 130), Anchor = topAnchor };
        Controls.Add(gbProgress);

        _progress = new ProgressBar { Location = new Point(16, 28), Size = new Size(764, 26), Maximum = 100, Style = ProgressBarStyle.Continuous, Anchor = topAnchor };
        _lblStatus = new Label { Text = "Status: idle", Location = new Point(16, 62), AutoSize = true };
        _lblLength = new Label { Text = "Current length: -", Location = new Point(16, 88), AutoSize = true };
        _lblAttempts = new Label { Text = "Attempts: 0", Location = new Point(220, 88), AutoSize = true };
        _lblElapsed = new Label { Text = "Elapsed: 00:00.000", Location = new Point(16, 110), AutoSize = true };
        _lblSpeed = new Label { Text = "Speed: -", Location = new Point(220, 110), AutoSize = true };

        gbProgress.Controls.AddRange(new Control[] { _progress, _lblStatus, _lblLength, _lblAttempts, _lblElapsed, _lblSpeed });

        var gbResult = new GroupBox { Text = "4. Result / log", Location = new Point(12, 450), Size = new Size(796, 318), Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right };
        Controls.Add(gbResult);

        _txtLog = new TextBox
        {
            Location = new Point(16, 26), Size = new Size(764, 280), Multiline = true, ReadOnly = true,
            ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 9f),
            BackColor = Color.FromArgb(24, 24, 24), ForeColor = Color.Gainsboro,
            Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
        };
        gbResult.Controls.Add(_txtLog);
    }
}
