jQuery(function($) {
	/**
	 * General variables
	 */
	var adminbarHeight = $('#wpadminbar').length > 0 ? $('#wpadminbar').height() : 0;
	var siteheaderHeight = $('.site-header').length > 0 ? $('.site-header').height() : 0;
	$(window).resize(function() {
		adminbarHeight = $('#wpadminbar').length > 0 ? $('#wpadminbar').height() : 0;
		siteheaderHeight = $('.site-header').length > 0 ? $('.site-header').height() : 0;
	});

});

jQuery(document).ready(function($) {

    /** Autocomplete Search **/

    function normalize(str) {

        str = str.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();
        //str = str.replace(':', '');

        return str;

    }

    function highlightText(title, query) {

        const normTitle = normalize(title);
        const normQuery = normalize(query);

        const index = normTitle.indexOf(normQuery);

        if (index === -1) return title;

        const realStart = index;
        const realEnd = index + query.length;

        return (title.slice(0, realStart) + "<strong>" + title.slice(realStart, realEnd) + "</strong>" + title.slice(realEnd));

    }

    const searchClose = document.getElementById('searchClose');
    const suggestions = document.getElementById('search-results-container');

    searchClose.addEventListener('click', function () {
        suggestions.hidden = true;
    });

    document.getElementById('headerSearchInput').addEventListener('input', async function () {

        // Match google package first
        const match = this.value.match(/id=([a-zA-Z0-9._-]+)/);

        if (match) {
            this.value = match[1];
        }

        // Doing suggest

        const fragment = document.createDocumentFragment();

        let query = this.value.trim().toLowerCase();

        if (query.length == 0) {

            suggestions.hidden = true;

            return;

        } else {
            suggestions.hidden = false;
        }

        try {

            const response = await fetch('https://liteapks.com/snippets/search?s=' + query);

            const data = await response.json();

            suggestions.innerHTML = '';

            data.forEach(item => {

                let title = item.name;
                let icon = item.icon;
                let url = item.url;

                const divElement = document.createElement('div');
                divElement.className = 'search-result';

                const aElement = document.createElement('a');
                aElement.className = 'clickable truncate';
                aElement.href = url;

                // Create image element
                const imgElement = document.createElement('img');
                imgElement.src = icon;
                imgElement.alt = title;
                imgElement.width = 25;
                imgElement.height = 25;
                imgElement.loading = 'lazy';
                imgElement.decoding = 'async';
                imgElement.classList.add('loaded');

                const regex = new RegExp('(' + query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'ig');

                let titleHighlighted = highlightText(title, query);
                let displayTitle = titleHighlighted;

                const titleSpan = document.createElement('span');
                titleSpan.innerHTML = displayTitle;

                aElement.appendChild(imgElement);
                aElement.appendChild(titleSpan)

                divElement.appendChild(aElement);
                fragment.appendChild(divElement);

            });

            suggestions.appendChild(fragment);

        } catch (err) {

        }

    });

});

jQuery(document).ready(function($) {

    'use strict';

    // View toggle
    const gridBtn = document.getElementById('grid-btn');
    const listBtn = document.getElementById('list-btn');
    const container = document.getElementById('games-container');
    const grid = document.getElementById('games-grid');

    if (gridBtn && listBtn && container && grid) {
        const GRID_COLS = ['grid-cols-2', 'sm:grid-cols-3', 'md:grid-cols-4', 'lg:grid-cols-5', 'xl:grid-cols-6'];

        function applyViewClasses(view) {
            const isGrid = view === 'grid';

            container.classList.toggle('grid-view', isGrid);
            container.classList.toggle('list-view', !isGrid);

            if (isGrid) {
                grid.classList.remove('grid-cols-1', 'gap-0');
                GRID_COLS.forEach(c => grid.classList.add(c));
                grid.classList.add('gap-4');
            } else {
                GRID_COLS.forEach(c => grid.classList.remove(c));
                grid.classList.remove('gap-4');
                grid.classList.add('grid-cols-1', 'gap-0');
            }

            gridBtn.classList.toggle('bg-white', isGrid);
            gridBtn.classList.toggle('shadow-sm', isGrid);
            gridBtn.classList.toggle('text-primary', isGrid);
            gridBtn.classList.toggle('text-gray', !isGrid);
            gridBtn.setAttribute('aria-pressed', String(isGrid));

            listBtn.classList.toggle('bg-white', !isGrid);
            listBtn.classList.toggle('shadow-sm', !isGrid);
            listBtn.classList.toggle('text-primary', !isGrid);
            listBtn.classList.toggle('text-gray', isGrid);
            listBtn.setAttribute('aria-pressed', String(!isGrid));

            // Badge position: grid → top-5 left-5 | list → top-1 left-4
            document.querySelectorAll('.app-badge-wrap').forEach(function (el) {
                if (isGrid) {
                    el.classList.remove('top-1', 'left-4');
                    el.classList.add('top-5', 'left-5');
                } else {
                    el.classList.remove('top-5', 'left-5');
                    el.classList.add('top-1', 'left-4');
                }
            });
        }

        function persistView(view) {
            localStorage.setItem('gameView', view);
            document.cookie = 'currentLayout=' + view + ';path=/;max-age=31536000;SameSite=Lax';
        }

        function setView(view, animate) {
            persistView(view);
            if (!animate) {
                applyViewClasses(view);
                return;
            }
            grid.style.transition = 'opacity 140ms ease';
            grid.style.opacity = '0';
            setTimeout(function () {
                applyViewClasses(view);
                grid.style.opacity = '1';
                setTimeout(function () { grid.style.transition = ''; }, 140);
            }, 140);
        }

        gridBtn.addEventListener('click', () => setView('grid', true));
        listBtn.addEventListener('click', () => setView('list', true));

        // On page load: silently correct if localStorage differs from PHP-rendered layout.
        // Also syncs cookie so the two sources stay in agreement going forward.
        const saved = localStorage.getItem('gameView');
        if (saved) {
            const rendered = container.classList.contains('list-view') ? 'list' : 'grid';
            if (saved !== rendered) applyViewClasses(saved);
            persistView(saved);
        }
    }



    /**
     * CONSTANTS
     */
    const TOAST_DURATION = 3000;
    const TOAST_EXTRA_DURATION = 5000;
    const SCROLL_DURATION = 600;

    /**
     * Fetch Fresh Nonce
     * @returns {Promise<string>} - Promise resolving to nonce string
     */
    function fetchNonce(type) {
        return new Promise(function (resolve, reject) {
            $.ajax({
                type: 'POST',
                url: ajax.ajax_url,
                data: {
                    'action': 'app_get_nonce',
                    'type': type
                },
                dataType: 'json',
                success: function (response) {
                    if (response && response.success && response.data && response.data.nonce) {
                        resolve(response.data.nonce);
                    } else {
                        reject(new Error('Failed to fetch nonce'));
                    }
                },
                error: function (jqXHR) {
                    reject(jqXHR);
                }
            });
        });
    }

    /**
     * Bổ sung token cho link trỏ thẳng tới worker tải xuống của mình (.dl-item).
     *
     * Khối "Original file on Google Play" render link trần; đa số trỏ Google Play /
     * gp*.liteapks.com (không có cổng chặn) nên giữ nguyên. Riêng số ít bản ghi trỏ
     * download*.liteapks.dev sẽ bị cổng chặn trả 403 nếu thiếu token → gắn token
     * ngay lúc click, cùng cách với luồng tải chính (btoa(btoa(now+3h))).
     */
    const WORKER_DOWNLOAD_HOSTS = ['download.liteapks.dev', 'download-old.liteapks.dev'];

    document.addEventListener('click', function (e) {
        const link = e.target.closest ? e.target.closest('a.dl-item') : null;
        if (!link || !link.href) return;

        let url;
        try {
            url = new URL(link.href, window.location.href);
        } catch (err) {
            return;
        }
        if (WORKER_DOWNLOAD_HOSTS.indexOf(url.hostname) === -1) return;
        if (url.searchParams.has('token')) return;

        const timeToLive = Math.floor(Date.now() / 1000) + 3600 * 3;
        url.searchParams.set('token', btoa(btoa(timeToLive)));
        link.href = url.toString();
    }, true);

    /**
     * AJAX Download Flow
     */
    const downloadContainer = document.getElementById('download');
    const loadingContainer  = document.getElementById('download-loading');
    const loadedContainer   = document.getElementById('download-loaded');
    const linkBtn           = document.getElementById('download-loaded-link');
    const progressFill      = document.getElementById('download-progress-fill');
    const loadingText       = document.getElementById('download-loading-text');

    if (downloadContainer && loadingContainer && loadedContainer && linkBtn) {
        
        const postId = parseInt(downloadContainer.dataset.postId, 10);
        const encodedLink = downloadContainer.dataset.link;
        
        if (postId > 0 && encodedLink) {
            const TOTAL_WAIT_MS = 5000;

            // Start progress bar animation ensuring transition triggers
            setTimeout(function() {
                if(progressFill) {
                    progressFill.style.transition = 'width 5s linear';
                    progressFill.style.width = '100%';
                }
            }, 50);

            // Decode link immediately and set href
            let downloadUrl;
            try {
                const decodedUrl = atob(encodedLink);
                if (decodedUrl) {
                    downloadUrl = decodedUrl;
                } else {
                    throw new Error('Invalid link data');
                }
            } catch (err) {
                if(progressFill) progressFill.style.backgroundColor = '#ef4444'; // red
                if(loadingText) {
                    loadingText.classList.add('text-red');
                    loadingText.textContent = 'Error: Failed to decode link';
                }
                return; // Stop execution on error
            }

            const timeToLive = Math.floor(Date.now() / 1000) + 3600 * 3;
            const token = btoa(btoa(timeToLive));

            // Delay setting the URL by 3 seconds
            setTimeout(function() {
                linkBtn.href = downloadUrl + '?token=' + encodeURIComponent(token);
            }, 3000);

            // The literal 5-second timer only handles the UI unlocking now
            setTimeout(function() {
                // Unlock the button visually
                linkBtn.classList.remove('pointer-events-none', 'opacity-50');
                linkBtn.classList.add('hover:-translate-y-1');

                // Transition UI
                loadingContainer.style.opacity = '0';
                setTimeout(function() {
                    loadingContainer.style.display = 'none';
                    loadedContainer.classList.remove('hidden');
                    // slight reflow delay
                    setTimeout(function() {
                        loadedContainer.style.opacity = '1';
                    }, 50);
                }, 300);
            }, TOTAL_WAIT_MS);
        }
    }

    /**
     * Comment Reply
     * Allows replying to both parent comments and child comments
     */
    $(document).on('click', '.comment-reply-btn', function (e) {
        e.preventDefault();

        const $btn = $(this);
        const parentId = $btn.data('parent');
        const replyToId = $btn.data('reply-to') || parentId;
        const authorName = $btn.data('author') || '';
        const parentAuthorName = $btn.data('parent-author') || '';
        const $form = $('#comment-form');
        const $parentInput = $('#comment-parent');
        const $replyIndicator = $('#reply-indicator');
        const $replyToName = $('#reply-to-name');
        const $replyToParentInfo = $('#reply-to-parent-info');
        const $replyToParentName = $('#reply-to-parent-name');

        if (!$form.length) return;

        $parentInput.val(parentId || 0);

        let $replyToInput = $('#comment-reply-to');
        if (!$replyToInput.length) {
            $form.append('<input type="hidden" name="reply_to" id="comment-reply-to" value="0">');
            $replyToInput = $('#comment-reply-to');
        }
        $replyToInput.val(replyToId || parentId || 0);

        if (parentId && authorName) {
            $replyToName.text(authorName);
            $replyIndicator.removeClass('hidden');

            if (parentAuthorName && replyToId !== parentId) {
                $replyToParentName.text(parentAuthorName);
                $replyToParentInfo.removeClass('hidden');
            } else {
                $replyToParentInfo.addClass('hidden');
            }
        } else {
            $replyIndicator.addClass('hidden');
            $replyToParentInfo.addClass('hidden');
        }

        const adminbarHeight = $('#wpadminbar').length ? 32 : 0;
        const headerOuterHeight = $('#header').length ? $('#header').outerHeight() : 0;
        const scrollOffset = adminbarHeight + headerOuterHeight + 20;

        $('html, body').animate({
            scrollTop: $form.offset().top - scrollOffset
        }, SCROLL_DURATION, function () {
            $('#comment-input').focus();
        });
    });

    /**
     * Cancel Reply
     */
    $(document).on('click', '#cancel-reply', function (e) {
        e.preventDefault();

        const $parentInput = $('#comment-parent');
        const $replyIndicator = $('#reply-indicator');
        const $replyToParentInfo = $('#reply-to-parent-info');

        $parentInput.val(0);
        const $replyToInput = $('#comment-reply-to');
        if ($replyToInput.length) {
            $replyToInput.val(0);
        }
        $replyIndicator.addClass('hidden');
        $replyToParentInfo.addClass('hidden');
        $('#reply-to-name').text('');
        $('#reply-to-parent-name').text('');
        $('#comment-input').focus();
    });

    $('.form-comment').on('submit', function (e) {
        e.preventDefault();

        const $form = $(this);
        const $submitBtn = $form.find('[type="submit"]');
        const $commentField = $form.find('[name="comment"]');
        const $nameField = $form.find('[name="name"]');
        const $emailField = $form.find('[name="email"]');

        const comment = $commentField.val().trim();
        const name = $nameField.val().trim();
        const email = $emailField.val().trim();

        if (!comment) {
            if (typeof showToast === 'function') {
                showToast('Please input your comment.', 'error', TOAST_DURATION);
            }
            $commentField.focus();
            return;
        }

        if (!name) {
            if (typeof showToast === 'function') {
                showToast('Please input your name.', 'error', TOAST_DURATION);
            }
            $nameField.focus();
            return;
        }

        if (!email) {
            if (typeof showToast === 'function') {
                showToast('Please input your email.', 'error', TOAST_DURATION);
            }
            $emailField.focus();
            return;
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            if (typeof showToast === 'function') {
                showToast('Please enter a valid email address.', 'error', TOAST_DURATION);
            }
            $emailField.focus();
            return;
        }

        $submitBtn.prop('disabled', true);
        const originalHtml = $submitBtn.html();

        $submitBtn.html('<svg class="size-5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg> <span class="submit-text">Sending...</span>');

        fetchNonce('comment')
            .then(function (nonce) {
                return $.ajax({
                    type: 'POST',
                    url: ajax.ajax_url,
                    data: $form.serialize() + '&app_comment_nonce=' + encodeURIComponent(nonce),
                    dataType: 'json'
                });
            })
            .then(function (data) {
                if (typeof data === 'string') {
                    try {
                        data = JSON.parse(data);
                    } catch (e) {
                        data = { status: false, message: 'Invalid response from server.' };
                    }
                }

                $submitBtn.prop('disabled', false);
                $submitBtn.html(originalHtml);

                if (data && data.status === true) {
                    $form[0].reset();
                    $('#comment-parent').val(0);
                    const $replyToInput = $('#comment-reply-to');
                    if ($replyToInput.length) {
                        $replyToInput.val(0);
                    }
                    $('#reply-indicator').addClass('hidden');
                    $('#reply-to-parent-info').addClass('hidden');
                    $('#reply-to-name').text('');
                    $('#reply-to-parent-name').text('');

                    const toastType = data.type || 'success';
                    if (typeof showToast === 'function') {
                        showToast(data.message || 'Thank you for your comment. It will be reviewed by the admin and published soon.', toastType, TOAST_EXTRA_DURATION);
                    } else {
                        $form.append('<div class="mt-3 p-3 bg-green-50 border border-green-200 rounded-xl text-green-700 text-sm">' + (data.message || 'Thank you for your comment. It will be reviewed by the admin and published soon.') + '</div>');
                    }
                } else {
                    const toastType = (data && data.type) ? data.type : 'error';
                    const message = (data && data.message) ? data.message : 'An error occurred. Please try again.';
                    if (typeof showToast === 'function') {
                        showToast(message, toastType, TOAST_DURATION);
                    } else {
                        $form.append('<div class="mt-3 p-3 bg-red-50 border border-red-200 rounded-xl text-red-700 text-sm">' + message + '</div>');
                    }
                }
            })
            .catch(function (error) {
                $submitBtn.prop('disabled', false);

                const $submitIcon = $submitBtn.find('#comment-submit-icon');
                if ($submitIcon.length) {
                    $submitIcon.removeClass('animate-spin');
                } else {
                    $submitBtn.html(originalHtml);
                }

                const $submitText = $submitBtn.find('.submit-text');
                if ($submitText.length) {
                    $submitText.text('Send');
                }

                const errorMessage = (error.responseJSON && error.responseJSON.message) ? error.responseJSON.message : (error.message || 'An error occurred. Please try again.');
                if (typeof showToast === 'function') {
                    showToast(errorMessage, 'error', TOAST_DURATION);
                }
            });
    });

    /**
     * User Rating (rateYo)
     * Requires: rateyo-js enqueued as dependency before site-js on single post pages.
     */
    const $rateYoEl = $('#rateyo-widget');
    if ($rateYoEl.length && typeof $.fn.rateYo !== 'undefined') {
        const postId        = parseInt($rateYoEl.data('post-id'), 10);
        const hasRated      = $rateYoEl.data('has-rated') === 1 || $rateYoEl.data('has-rated') === '1';
        const ratedLocalKey = 'rated_' + postId;
        const ratedLocalExp = parseInt(localStorage.getItem(ratedLocalKey), 10);
        const hasRatedLocal = ratedLocalExp > Date.now();
        const isReadOnly    = hasRated || hasRatedLocal;
        const rating        = parseFloat($rateYoEl.data('rating')) || 0;

        $rateYoEl.rateYo({
            rating:     rating,
            fullStar:   true,
            starWidth:  '30px',
            normalFill: '#dadce0',
            ratedFill:  '#e8710a',
            readOnly:   isReadOnly,
        });

        if (isReadOnly && hasRatedLocal && !hasRated) {
            $rateYoEl.next('.rateyo-label').text('You already rated');
        }

        if (!isReadOnly) {
            $rateYoEl.on('rateyo.set', function (e, data) {
                // Pre-check localStorage before any network call.
                // Catches the multi-tab race: another tab may have rated since this page loaded.
                if (parseInt(localStorage.getItem(ratedLocalKey), 10) > Date.now()) {
                    $rateYoEl.rateYo('option', 'readOnly', true);
                    $rateYoEl.next('.rateyo-label').text('You already rated');
                    if (typeof showToast === 'function') {
                        showToast('You already rated this post.', 'warning', TOAST_DURATION);
                    }
                    return;
                }

                // Lock the widget and set the optimistic localStorage lock before the network call.
                // localStorage is shared across tabs — any other open tab will see this immediately.
                $rateYoEl.rateYo('option', 'readOnly', true);
                localStorage.setItem(ratedLocalKey, String(Date.now() + 365 * 24 * 3600 * 1000));

                fetchNonce('rating')
                    .then(function (nonce) {
                        return $.ajax({
                            type:     'POST',
                            url:      ajax.ajax_url,
                            data:     {
                                action:           'app_rating',
                                post_id:          postId,
                                rating:           data.rating,
                                app_rating_nonce: nonce,
                            },
                            dataType: 'json',
                        });
                    })
                    .then(function (res) {
                        if (res && res.status) {
                            // Unbind before programmatic rating update to prevent rateyo.set re-firing
                            $rateYoEl.off('rateyo.set');
                            if (res.new_avg) {
                                $('.rating-big .number').text(res.new_avg);
                                $rateYoEl.rateYo('option', 'rating', res.new_avg);
                            }
                            $rateYoEl.next('.rateyo-label').text('You already rated');
                            if (typeof showToast === 'function') {
                                showToast(res.message || 'Thank you for your rating!', 'success', TOAST_DURATION);
                            }
                        } else {
                            // Keep locked on "already rated" warning; unlock only on real errors
                            if (!res || res.type !== 'warning') {
                                localStorage.removeItem(ratedLocalKey);
                                $rateYoEl.rateYo('option', 'readOnly', false);
                            }
                            if (typeof showToast === 'function') {
                                showToast((res && res.message) || 'An error occurred.', (res && res.type) || 'error', TOAST_DURATION);
                            }
                        }
                    })
                    .catch(function (jqXHR) {
                        // jQuery rejects the promise for any 4xx/5xx — inspect the body first.
                        const errRes = jqXHR && jqXHR.responseJSON;
                        if (errRes && errRes.type === 'warning') {
                            $rateYoEl.next('.rateyo-label').text('You already rated');
                            if (typeof showToast === 'function') {
                                showToast(errRes.message || 'You already rated this post.', 'warning', TOAST_DURATION);
                            }
                        } else {
                            localStorage.removeItem(ratedLocalKey);
                            $rateYoEl.rateYo('option', 'readOnly', false);
                            if (typeof showToast === 'function') {
                                showToast('An error occurred. Please try again.', 'error', TOAST_DURATION);
                            }
                        }
                    });
            });
        }
    }

    /* Request Help Modal */

    const requestHelpButton = $('#request-help-button');
    const helpModal = $('#help-modal');
    const closeHelpButton = $('#help-modal-close');

    if (requestHelpButton) {

        requestHelpButton.on('click', function () {

            helpModal.addClass('active');

            setTimeout(function() {

                const urlField = $('#nf-field-38');
                urlField.val(window.location.href);
                urlField.prop('disabled', true);

            }, 500);

        });

    }

    if (closeHelpButton) {

        closeHelpButton.on('click', function () {
            helpModal.removeClass('active');
        });

    }

    if (helpModal) {

        helpModal.on('click', function (e) {

            if ($(e.target).is(helpModal)) {
                helpModal.removeClass('active');
            }

        });

    }

    /**
     * Request Update Modal Handler
     */
    const $requestUpdateTrigger = $('#request-update-btn');
    const $requestUpdateModal   = $('#requestUpdateModal');
    const $requestUpdateForm    = $('#requestUpdateForm');
    const $requestUpdateSubmit  = $('#requestUpdateSubmit');

    if ($requestUpdateTrigger.length) {
        const rawPostId = $requestUpdateTrigger.data('post-id');
        const requestUpdatePostId  = parseInt(rawPostId, 10);

        if (!rawPostId || isNaN(requestUpdatePostId) || requestUpdatePostId <= 0) {

            if (typeof showToast === 'function') {
                showToast('Invalid application. Please refresh the page.', 'error', TOAST_DURATION);
            }
            return;
        }

        const reqLocalKey          = 'req_update_' + requestUpdatePostId;

        // Disable button at init if already requested (localStorage — shared across tabs, survives reload).
        // HttpOnly cookies are invisible to JS, so localStorage is the only reliable client-side check.
        const reqLocalExp = parseInt(localStorage.getItem(reqLocalKey), 10);
        if (reqLocalExp > Date.now()) {
            $requestUpdateTrigger.prop('disabled', true).css('opacity', '0.6');
        }

        function openRequestUpdateModal() {
            $requestUpdateModal.addClass('active');
            $('body').css('overflow', 'hidden');
            setTimeout(function () { $('#requestNewVersion').focus(); }, 50);
        }

        function closeRequestUpdateModal() {
            $requestUpdateModal.removeClass('active');
            $('body').css('overflow', '');
            $requestUpdateForm[0].reset();
            $requestUpdateForm.find('.modal-input').removeClass('input-error');
        }

        $requestUpdateTrigger.on('click', function () {
            if ($(this).prop('disabled')) return;
            openRequestUpdateModal();
        });

        $('#requestUpdateClose, #requestUpdateCancel').on('click', closeRequestUpdateModal);

        $requestUpdateModal.on('click', function (e) {
            if ($(e.target).is($requestUpdateModal)) closeRequestUpdateModal();
        });

        $(document).on('keydown.requestModal', function (e) {
            if (e.key === 'Escape' && $requestUpdateModal.hasClass('active')) closeRequestUpdateModal();
        });

        $requestUpdateForm.on('submit', function (e) {
            e.preventDefault();

            const $newVersionInput = $('#requestNewVersion');
            const $sourceInput     = $('#requestSource');
            const newVersion       = $newVersionInput.val().trim();
            const source           = $sourceInput.val().trim();

            $requestUpdateForm.find('.modal-input').removeClass('input-error');

            if (!newVersion) {
                $newVersionInput.addClass('input-error').focus();
                if (typeof showToast === 'function') showToast('Please enter the new version.', 'error', TOAST_DURATION);
                return;
            }

            if (!source) {
                $sourceInput.addClass('input-error').focus();
                if (typeof showToast === 'function') showToast('Please enter a source reference.', 'error', TOAST_DURATION);
                return;
            }

            // Pre-check localStorage before any network call.
            if (parseInt(localStorage.getItem(reqLocalKey), 10) > Date.now()) {
                closeRequestUpdateModal();
                $requestUpdateTrigger.prop('disabled', true).css('opacity', '0.6');
                if (typeof showToast === 'function') {
                    showToast('You have already requested an update for this post today.', 'warning', TOAST_DURATION);
                }
                return;
            }

            const originalHtml = $requestUpdateSubmit.html();
            $requestUpdateSubmit.prop('disabled', true).html(
                '<svg class="w-4 h-4 animate-spin shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg> Submitting...'
            );

            // Set optimistic localStorage lock before the network call (shared across tabs).
            localStorage.setItem(reqLocalKey, String(Date.now() + 24 * 3600 * 1000));

            fetchNonce('request_update')
                .then(function (nonce) {
                    return $.ajax({
                        type: 'POST',
                        url: ajax.ajax_url,
                        data: {
                            action:               'app_request_update',
                            post_id:              requestUpdatePostId,
                            new_version:          newVersion,
                            source_reference:     source,
                            request_update_nonce: nonce,
                        },
                        dataType: 'json',
                    });
                })
                .then(function (response) {
                    $requestUpdateSubmit.prop('disabled', false).html(originalHtml);

                    if (response && response.status === true) {
                        closeRequestUpdateModal();
                        $requestUpdateTrigger.prop('disabled', true).css('opacity', '0.6');
                        const toastType = response.type || 'success';
                        if (typeof showToast === 'function') {
                            showToast(response.message || 'Your update request has been submitted successfully.', toastType, TOAST_EXTRA_DURATION);
                        }
                    } else {
                        // Keep button disabled on "already requested" warning; unlock only on real errors
                        if (!response || response.type !== 'warning') {
                            localStorage.removeItem(reqLocalKey);
                            $requestUpdateSubmit.prop('disabled', false).html(originalHtml);
                        }
                        const toastType = (response && response.type) ? response.type : 'error';
                        const message   = (response && response.message) ? response.message : 'An error occurred. Please try again.';
                        if (typeof showToast === 'function') {
                            showToast(message, toastType, TOAST_DURATION);
                        }
                    }
                })
                .catch(function (jqXHR) {
                    // jQuery rejects for 4xx/5xx — inspect the body first.
                    const errRes = jqXHR && jqXHR.responseJSON;
                    if (errRes && errRes.type === 'warning') {
                        // Server blocked as duplicate — close modal, keep button disabled
                        closeRequestUpdateModal();
                        $requestUpdateTrigger.prop('disabled', true).css('opacity', '0.6');
                        if (typeof showToast === 'function') {
                            showToast(errRes.message || 'You have already requested an update for this post today.', 'warning', TOAST_DURATION);
                        }
                    } else {
                        localStorage.removeItem(reqLocalKey);
                        $requestUpdateSubmit.prop('disabled', false).html(originalHtml);
                        const errorMessage = (errRes && errRes.message) ? errRes.message : 'An error occurred. Please try again.';
                        if (typeof showToast === 'function') {
                            showToast(errorMessage, 'error', TOAST_DURATION);
                        }
                    }
                });
        });
    }
});

/* Custom JS from single.html */

(function() {
    'use strict';

    // ===== SIDEBAR =====
    const menuToggle = document.getElementById('menuToggle');
    const sidebar = document.getElementById('sidebar');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    function openSidebar() { sidebar.classList.add('active'); sidebarOverlay.classList.add('active'); document.body.style.overflow = 'hidden'; }
    function closeSidebar() { sidebar.classList.remove('active'); sidebarOverlay.classList.remove('active'); document.body.style.overflow = ''; }
    menuToggle.addEventListener('click', openSidebar);
    sidebarOverlay.addEventListener('click', closeSidebar);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeSidebar(); });

    // ===== SEARCH =====
    const searchToggle = document.getElementById('searchToggle');
    const searchClose  = document.getElementById('searchClose');
    const headerDefault = document.getElementById('header-default');
    const headerSearch  = document.getElementById('header-search');
    const headerSearchInput = document.getElementById('headerSearchInput');

    function openSearch() {
        headerDefault.classList.add('opacity-0', 'pointer-events-none');
        headerSearch.classList.remove('opacity-0', 'pointer-events-none', 'translate-x-4');
        setTimeout(() => headerSearchInput?.focus(), 50);
    }
    function closeSearch() {
        headerSearch.classList.add('opacity-0', 'pointer-events-none', 'translate-x-4');
        headerDefault.classList.remove('opacity-0', 'pointer-events-none');
    }
    if (searchToggle) searchToggle.addEventListener('click', openSearch);
    if (searchClose)  searchClose.addEventListener('click', closeSearch);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !headerSearch.classList.contains('opacity-0')) closeSearch(); });

    // ===== CONTENT TABS =====
    const tabBtns = document.querySelectorAll('#contentTabs .content-tab');
    const tabContents = document.querySelectorAll('.tab-content');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(btn.dataset.tab).classList.add('active');
        });
    });

    // ===== READ MORE =====
    const descContent = document.getElementById('descContent');
    const readMoreBtn = document.getElementById('readMoreBtn');
    if (readMoreBtn && descContent) {
        readMoreBtn.addEventListener('click', () => {
            const expanded = descContent.classList.toggle('expanded');
            readMoreBtn.innerHTML = expanded
                ? 'Show less <svg class="w-4 h-4 ml-1 inline-block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"/></svg>'
                : 'Read more <svg class="w-4 h-4 ml-1 inline-block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>';
        });
    }

    // ===== WHAT'S NEW READ MORE =====
    const whatNewContent = document.getElementById('whatNewContent');
    const whatNewReadMoreBtn = document.getElementById('whatNewReadMoreBtn');
    if (whatNewReadMoreBtn && whatNewContent) {
        whatNewReadMoreBtn.addEventListener('click', () => {
            const expanded = whatNewContent.classList.toggle('expanded');
            whatNewReadMoreBtn.innerHTML = expanded
                ? 'Show less <svg class="w-4 h-4 ml-1 inline-block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"/></svg>'
                : 'Read more <svg class="w-4 h-4 ml-1 inline-block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>';
        });
    }

    // ===== LIGHTBOX =====
    const screenshots = document.querySelectorAll('#screenshotScroll img');
    const lightbox = document.getElementById('lightbox');
    const lightboxImg = document.getElementById('lightboxImg');
    const lightboxClose = document.getElementById('lightboxClose');
    const lightboxPrev = document.getElementById('lightboxPrev');
    const lightboxNext = document.getElementById('lightboxNext');
    let currentIdx = 0;
    const srcs = Array.from(screenshots).map(img => img.src);

    function showLightbox(idx) {
        currentIdx = idx;
        lightboxImg.src = srcs[idx];
        lightbox.classList.add('active');
        document.body.style.overflow = 'hidden';
    }
    function closeLightbox() {
        lightbox.classList.remove('active');
        document.body.style.overflow = '';
    }

    if (lightbox && lightboxClose && lightboxPrev && lightboxNext) {
        screenshots.forEach(img => {
            img.addEventListener('click', () => showLightbox(parseInt(img.dataset.idx)));
        });
        lightboxClose.addEventListener('click', closeLightbox);
        lightbox.addEventListener('click', (e) => { if (e.target === lightbox) closeLightbox(); });
        lightboxPrev.addEventListener('click', (e) => { e.stopPropagation(); currentIdx = (currentIdx - 1 + srcs.length) % srcs.length; lightboxImg.src = srcs[currentIdx]; });
        lightboxNext.addEventListener('click', (e) => { e.stopPropagation(); currentIdx = (currentIdx + 1) % srcs.length; lightboxImg.src = srcs[currentIdx]; });
        document.addEventListener('keydown', (e) => {
            if (!lightbox.classList.contains('active')) return;
            if (e.key === 'Escape') closeLightbox();
            if (e.key === 'ArrowLeft') { currentIdx = (currentIdx - 1 + srcs.length) % srcs.length; lightboxImg.src = srcs[currentIdx]; }
            if (e.key === 'ArrowRight') { currentIdx = (currentIdx + 1) % srcs.length; lightboxImg.src = srcs[currentIdx]; }
        });
    }

    // ===== COMMENT VOTE =====
    document.querySelectorAll('.comment-vote').forEach(btn => {
        btn.addEventListener('click', () => {
            const type = btn.dataset.type;
            if (type === 'like') btn.classList.toggle('liked');
            if (type === 'dislike') btn.classList.toggle('disliked');
        });
    });

    // ===== BOTTOM NAV =====
    document.querySelectorAll('.mobile-bottom-nav a').forEach(link => {
        link.addEventListener('click', () => {
            document.querySelectorAll('.mobile-bottom-nav a').forEach(l => { l.style.color = '#5f6368'; l.style.fontWeight = '500'; });
            link.style.color = '#01875f'; link.style.fontWeight = '600';
        });
    });

})();

/* ── Single Post: Share Button ── */
(function () {
    'use strict';
    var btn = document.querySelector('.js-share-btn');
    if (!btn) return;
    btn.addEventListener('click', function () {
        navigator.clipboard.writeText(btn.dataset.url).then(function () {
            if (typeof showToast === 'function') {
                showToast('Link copied!', 'success', 3000);
            }
        }).catch(function () {
            if (typeof showToast === 'function') {
                showToast('Could not copy link.', 'error', 3000);
            }
        });
    });
})();

/* ── Single Post/Tip: View Counter ── */
(function () {
    'use strict';

    if ( !ajax || !ajax.view_post_id ) return;

    const postId = parseInt( ajax.view_post_id, 10 );

    setTimeout( function () {
        jQuery.ajax({
            type:     'POST',
            url:      ajax.ajax_url,
            data:     { action: 'app_track_view', post_id: postId },
            dataType: 'json',
        });
    }, 3000 );
})();

/* ── Category Archive: Sort Select ── */
(function () {
    'use strict';

    /* ── Sort select: navigate on change ── */
    const sortDesktop = document.getElementById('sort-select-desktop');

    function onSortChange(e) {
        const url = new URL(e.target.dataset.baseUrl);
        url.searchParams.set('orderby', e.target.value);
        window.location.href = url.toString();
    }

    if (sortDesktop) sortDesktop.addEventListener('change', onSortChange);

})();


/* ── Category Archive: Show more sub-category pills ── */
(function () {
    'use strict';
    const btn  = document.getElementById('cats-more-btn');
    const wrap = document.getElementById('cat-filter-wrap');
    if (!btn || !wrap) return;
    btn.addEventListener('click', function () {
        document.querySelectorAll('.js-cat-extra').forEach(function (el) {
            el.classList.remove('hidden');
        });
        wrap.classList.remove('flex-nowrap', 'overflow-x-auto');
        wrap.classList.add('flex-wrap');
        btn.remove();
    });
})();


/* ── Homepage: Chart Tabs ── */
(function () {
    'use strict';
    const chartTabs = document.getElementById('chartTabs');
    if (!chartTabs) return;

    const tabs   = chartTabs.querySelectorAll('.tab-pill');
    const panels = document.querySelectorAll('.chart-panel');

    tabs.forEach(function (tab) {
        tab.addEventListener('click', function () {
            tabs.forEach(function (t) {
                t.classList.remove('active', 'bg-primary', 'text-white', 'border-primary');
                t.classList.add('bg-white', 'text-gray', 'border-muted');
            });
            tab.classList.add('active', 'bg-primary', 'text-white', 'border-primary');
            tab.classList.remove('bg-white', 'text-gray', 'border-muted');
            const target = tab.dataset.tab;
            panels.forEach(function (p) {
                p.style.display = (p.id === target) ? 'block' : 'none';
            });
        });
    });
})();

/**
 * menu & search
 */
(function(){
    'use strict';
    const $=s=>document.getElementById(s),$$=s=>document.querySelectorAll(s);

    const sb=$('sidebar'),ov=$('sidebarOverlay');
    $('menuToggle').onclick=()=>{sb.classList.remove('-translate-x-full');ov.classList.remove('opacity-0','pointer-events-none');ov.classList.add('opacity-100');document.body.style.overflow='hidden'};
    function closeSB(){sb.classList.add('-translate-x-full');ov.classList.add('opacity-0','pointer-events-none');ov.classList.remove('opacity-100');document.body.style.overflow=''}
    ov.onclick=closeSB;document.onkeydown=e=>{if(e.key==='Escape'){closeSB();closeSrc()}};

    const hd=$('header-default'),hs=$('header-search'),si=$('headerSearchInput');
    function openSrc(){hd.classList.add('opacity-0','pointer-events-none');hs.classList.remove('opacity-0','pointer-events-none','translate-x-4');setTimeout(()=>si?.focus(),50)}
    function closeSrc(){hs.classList.add('opacity-0','pointer-events-none','translate-x-4');hd.classList.remove('opacity-0','pointer-events-none')}
    $('searchToggle').onclick=openSrc;
    $('searchClose').onclick=closeSrc;

    // Scroll arrows
    $$('.scroll-arr').forEach(b=>b.onclick=()=>{const el=$(b.dataset.scroll);if(el)el.scrollBy({left:el.clientWidth*.7*+b.dataset.dir,behavior:'smooth'})});
})();


/* ── Single Download: Version Accordion Toggle ── */
(function () {
    'use strict';

    document.querySelectorAll('.dl-version-tab').forEach(function (tab) {
        tab.addEventListener('click', function () {
            const panel = this.nextElementSibling;
            const isActive = this.classList.contains('active');
            const parent = this.closest('#dl-versions, #dl-other-versions');

            if (parent) {
                parent.querySelectorAll('.dl-version-tab').forEach(function (t) {
                    t.classList.remove('active');
                });
                parent.querySelectorAll('.dl-version-panel').forEach(function (p) {
                    p.classList.remove('active');
                });
            }

            // Toggle current
            if (!isActive) {
                this.classList.add('active');
                panel.classList.add('active');
            }
        });
    });
})();

/**
 * Toast Message System (Common/Reusable)
 * Used by: Comments, Like/Dislike, Rating, Report Form, Request Update, etc.
 */
(function () {
    'use strict';

    window.showToast = function (message, type, duration) {
        // Wait for jQuery and DOM to be ready
        if (typeof jQuery === 'undefined') {
            setTimeout(function () {
                if (typeof jQuery !== 'undefined') {
                    window.showToast(message, type, duration);
                } else {
                    alert(message); // Fallback
                }
            }, 100);
            return;
        }

        var $ = jQuery;
        type = type || 'success';
        duration = duration || 3000;

        // Ensure DOM is ready
        $(function () {
            // Remove existing toast if any
            $('.toast-container').remove();

            // Determine colors and icon based on type
            // Modern, clean design with subtle backgrounds and colored icons
            var bgColorHex, textColorHex, iconBgHex, iconColorHex, borderColorHex, icon;
            switch (type) {
                case 'success':
                    bgColorHex = '#7bbf3a';
                    textColorHex = '#ffffff';
                    iconBgHex = '#ffffff';
                    iconColorHex = '#7bbf3a';
                    borderColorHex = '#a7f3d0';
                    icon = '<div style="background-color: ' + iconBgHex + '; border-radius: 50%; padding: 6px; display: flex; align-items: center; justify-content: center;"><svg class="w-4 h-4" fill="none" stroke="' + iconColorHex + '" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7"/></svg></div>';
                    break;
                case 'error':
                    bgColorHex = '#fef2f2'; // red-50
                    textColorHex = '#991b1b'; // red-800
                    iconBgHex = '#ef4444'; // red-500
                    iconColorHex = '#ffffff';
                    borderColorHex = '#fecaca'; // red-200
                    icon = '<div class="flex items-center justify-center rounded-full p-2" style="background-color: ' + iconBgHex + ';"><svg class="w-4 h-4" fill="none" stroke="' + iconColorHex + '" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M6 18L18 6M6 6l12 12"/></svg></div>';
                    break;
                case 'warning':
                    bgColorHex = '#fffbeb'; // amber-50
                    textColorHex = '#92400e'; // amber-800
                    iconBgHex = '#f59e0b'; // amber-500
                    iconColorHex = '#ffffff';
                    borderColorHex = '#fde68a'; // amber-200
                    icon = '<div style="background-color: ' + iconBgHex + '; border-radius: 50%; padding: 6px; display: flex; align-items: center; justify-content: center;"><svg class="w-4 h-4" fill="none" stroke="' + iconColorHex + '" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg></div>';
                    break;
                case 'info':
                    bgColorHex = '#eff6ff'; // blue-50
                    textColorHex = '#1e40af'; // blue-800
                    iconBgHex = '#3b82f6'; // blue-500
                    iconColorHex = '#ffffff';
                    borderColorHex = '#bfdbfe'; // blue-200
                    icon = '<div style="background-color: ' + iconBgHex + '; border-radius: 50%; padding: 6px; display: flex; align-items: center; justify-content: center;"><svg class="w-4 h-4" fill="none" stroke="' + iconColorHex + '" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg></div>';
                    break;
                default:
                    bgColorHex = '#f9fafb'; // gray-50
                    textColorHex = '#1f2937'; // gray-800
                    iconBgHex = '#6b7280'; // gray-500
                    iconColorHex = '#ffffff';
                    borderColorHex = '#e5e7eb'; // gray-200
                    icon = '<div style="background-color: ' + iconBgHex + '; border-radius: 50%; padding: 6px; display: flex; align-items: center; justify-content: center;"><svg class="w-4 h-4" fill="none" stroke="' + iconColorHex + '" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg></div>';
            }

            var escapedMessage = $('<div>').text(message).html();

            var $toast = $('<div>', {
                class: 'toast-container',
                css: {
                    'position': 'fixed',
                    'top': '5rem', // Position below header (header is sticky with ~70-80px height)
                    'left': '50%',
                    'transform': 'translateX(-50%) translateX(400px)', // Center horizontally, start off-screen
                    'z-index': '99999', // Very high z-index to appear above header (z-50)
                    'max-width': '28rem',
                    'width': 'calc(100% - 2rem)', // Full width minus padding on mobile
                    'opacity': '0',
                    'transition': 'transform 0.3s ease-out, opacity 0.3s ease-out'
                }
            });

            var $toastInner = $('<div>', {
                class: 'rounded-xl shadow-2xl border-2 px-4 py-3 flex items-center gap-3',
                css: {
                    'background-color': bgColorHex,
                    'color': textColorHex,
                    'border-color': borderColorHex
                }
            });

            $toastInner.append($('<div>', { class: 'flex-shrink-0', html: icon }));
            $toastInner.append($('<div>', { class: 'flex-1 text-sm font-medium', html: escapedMessage }));

            var closeBtnColorHex = textColorHex;
            var $closeBtn = $('<button>', {
                type: 'button',
                class: 'toast-close flex-shrink-0 hover:opacity-75 transition-opacity cursor-pointer',
                css: {
                    'color': closeBtnColorHex
                },
                'aria-label': 'Close',
                html: '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>'
            });

            $toastInner.append($closeBtn);
            $toast.append($toastInner);

            if ($('body').length === 0) {
                return;
            }

            $('body').append($toast);

            $toast[0].offsetHeight;

            setTimeout(function () {
                $toast.css({
                    'transform': 'translateX(-50%)',
                    'opacity': '1'
                });

            }, 50);

            $toast.find('.toast-close').on('click', function () {
                $toast.css({
                    'transform': 'translateX(-50%) translateX(400px)', // Slide out to right while maintaining center
                    'opacity': '0'
                });
                setTimeout(function () {
                    $toast.remove();
                }, 300);
            });

            setTimeout(function () {
                if ($toast.length) {
                    $toast.css({
                        'transform': 'translateX(-50%) translateX(400px)',
                        'opacity': '0'
                    });
                    setTimeout(function () {
                        $toast.remove();
                    }, 300);
                }
            }, duration);
        });
    };
})();



(function() {
    'use strict';

    // Custom Multi-Select Dropdown Functionality
    function initCustomSelect(wrapperId, triggerId, dropdownId, selectedTextId, options) {
        const wrapper = document.getElementById(wrapperId);
        const trigger = document.getElementById(triggerId);
        const dropdown = document.getElementById(dropdownId);
        const selectedText = document.getElementById(selectedTextId);

        if (!wrapper || !trigger || !dropdown || !selectedText) return;

        // Toggle dropdown on trigger click
        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const isActive = dropdown.classList.contains('active');

            // Close all other dropdowns
            document.querySelectorAll('.custom-select-dropdown.active').forEach(dd => {
                if (dd !== dropdown) {
                    dd.classList.remove('active');
                    dd.parentElement.querySelector('.custom-select-trigger').classList.remove('active');
                }
            });

            // Toggle current dropdown
            dropdown.classList.toggle('active');
            trigger.classList.toggle('active');
        });

        // Stop propagation on dropdown click
        dropdown.addEventListener('click', (e) => {
            e.stopPropagation();
        });

        // Update selected text based on checked options
        function updateSelectedText() {
            const checkedOptions = Array.from(dropdown.querySelectorAll('input:checked'));
            if (checkedOptions.length === 0) {
                selectedText.textContent = options.placeholder || 'Select...';
                selectedText.classList.remove('has-selection');
            } else if (checkedOptions.length === 1) {
                const label = checkedOptions[0].closest('.custom-select-option').querySelector('label').textContent;
                selectedText.textContent = label;
                selectedText.classList.add('has-selection');
            } else {
                selectedText.textContent = `${checkedOptions.length} selected`;
                selectedText.classList.add('has-selection');
            }
        }

        // Handle checkbox/radio changes
        dropdown.querySelectorAll('input').forEach(input => {
            input.addEventListener('change', () => {
                updateSelectedText();
            });
        });

        // Initial update
        updateSelectedText();
    }

// Initialize all custom selects
    initCustomSelect('genre-select-wrapper', 'genre-select-trigger', 'genre-dropdown', 'genre-selected-text', {placeholder: 'Select Genre'});
    initCustomSelect('collection-select-wrapper', 'collection-select-trigger', 'collection-dropdown', 'collection-selected-text', {placeholder: 'Select Collection'});
    initCustomSelect('type-select-wrapper', 'type-select-trigger', 'type-dropdown', 'type-selected-text', {placeholder: 'Select App Type'});
    initCustomSelect('sort-select-wrapper', 'sort-select-trigger', 'sort-dropdown', 'sort-selected-text', {placeholder: 'Select Sort'});

// Close dropdowns when clicking outside
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.custom-select-wrapper')) {
            document.querySelectorAll('.custom-select-dropdown.active').forEach(dropdown => {
                dropdown.classList.remove('active');
                dropdown.parentElement.querySelector('.custom-select-trigger').classList.remove('active');
            });
        }
    });

// Selected Filters Badge Management will be initialized dynamically

// SVG Icons - converted from PHP svg_icons() function
    const svgIcons = {
        '': '',
        'sort': '<svg class="inline" xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" width="20px" height="20px" fill="#000000"><path d="M144-264v-72h240v72H144Zm0-180v-72h432v72H144Zm0-180v-72h672v72H144Z"/></svg>',
        'collection': '<svg class="inline" xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" width="18px" height="18px" fill="#000000"><path d="m276-528 204-336 204 336H276ZM696-96q-70 0-119-49t-49-119q0-70 49-119t119-49q70 0 119 49t49 119q0 70-49 119T696-96Zm-552-24v-288h288v288H144Zm551.77-48Q736-168 764-195.77q28-27.78 28-68Q792-304 764.23-332q-27.78-28-68-28Q656-360 628-332.23q-28 27.78-28 68Q600-224 627.77-196q27.78 28 68 28ZM216-192h144v-144H216v144Zm188-408h152l-76-125-76 125Zm76 0ZM360-336Zm331 67Z"/></svg>',
        'genre': '<svg class="inline" xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" width="20px" height="20px" fill="#000000"><path d="m251-444 229 132 230-132-194-111v147h-72v-147L251-444Zm193-195v-14q-42.24-12.32-69.12-46.92-26.88-34.6-26.88-80.1 0-54.98 38.72-93.48 38.72-38.5 93.5-38.5t93.28 38.6q38.5 38.6 38.5 93.21 0 45.19-26.88 79.99T516-653v14l264 153q17.1 9.62 26.55 25.81Q816-444 816-424v104q0 20-9.45 36.19Q797.1-267.63 780-258L516-105q-17.13 10-36.07 10Q461-95 444-105L180-258q-17.1-9.63-26.55-25.81Q144-300 144-320v-104q0-20 9.45-36.19Q162.9-476.38 180-486l264-153Zm0 389L216-382v62l264 152 264-152v-62L516-250q-17.13 10-36.07 10Q461-240 444-250Zm36-470q25 0 42.5-17.5T540-780q0-25-17.5-42.5T480-840q-25 0-42.5 17.5T420-780q0 25 17.5 42.5T480-720Zm0 552Z"/></svg>',
        'type': '<svg xmlns="http://www.w3.org/2000/svg" height="20px" viewBox="0 -960 960 960" width="20px" fill="#000000"><path d="M384-144H216q-29.7 0-50.85-21.15Q144-186.3 144-216v-168q40-2 68-29.5t28-66.5q0-39-28-66.5T144-576v-168q0-29.7 21.15-50.85Q186.3-816 216-816h168q0-40 27.77-68 27.78-28 68-28Q520-912 548-884.16q28 27.84 28 68.16h168q29.7 0 50.85 21.15Q816-773.7 816-744v168q40 0 68 27.77 28 27.78 28 68Q912-440 884.16-412q-27.84 28-68.16 28v168q0 29.7-21.15 50.85Q773.7-144 744-144H576q-2-40-29.38-68t-66.5-28q-39.12 0-66.62 28-27.5 28-29.5 68Zm-168-72h112q20-45 61.5-70.5T480-312q49 0 90.5 25.5T632-216h112v-240h72q9.6 0 16.8-7 7.2-7 7.2-17t-7.2-17q-7.2-7-16.8-7h-72v-240H504v-72q0-9.6-7-16.8-7-7.2-17-7.2t-17 7.2q-7 7.2-7 16.8v72H216v112q45 20 70.5 61.5T312-480q0 50.21-25.5 91.6Q261-347 216-328v112Zm264-264Z"/></svg>',
        'reload': '<svg class="inline" xmlns="http://www.w3.org/2000/svg" viewBox="0 -960 960 960" width="20px" height="20px" fill="#000000"><path d="M480-192q-120 0-204-84t-84-204q0-120 84-204t204-84q65 0 120.5 27t95.5 72v-99h72v240H528v-72h131q-29-44-76-70t-103-26q-90 0-153 63t-63 153q0 90 63 153t153 63q84 0 144-55.5T693-456h74q-9 112-91 188t-196 76Z"/></svg>'
    };

    function getSvgIcon(key = '') {
        if (key && svgIcons.hasOwnProperty(key)) {
            return svgIcons[key];
        }
        return '';
    }

// Filter configuration mapping
    const filterConfig = {
        'genre': {label: 'Genre', name: 'genre[]', iconKey: 'genre'},
        'collection': {label: 'Collection', name: 'collection[]', iconKey: 'collection'},
        'type': {label: 'App Type', name: 'type[]', iconKey: 'type'},
        'sort': {label: 'Sort', name: 'sort', iconKey: 'sort'}
    };

// Function to update selected filters badges
    function updateSelectedFilters() {
        const selectedFiltersContainer = document.getElementById('selected-filters-container');
        const selectedFiltersDiv = document.getElementById('selected-filters');
        if (!selectedFiltersDiv) return;

        // Clear existing badges
        selectedFiltersDiv.innerHTML = '';

        // Collect all selected filters
        const selectedFilters = [];

        // Get all checked checkboxes within filter dropdowns only (genre, collection, type)
        document.querySelectorAll('.custom-select-dropdown input[type="checkbox"]:checked').forEach(checkbox => {
            const name = checkbox.name;
            const value = checkbox.value;
            const optionElement = checkbox.closest('.custom-select-option');

            // Skip if not in a valid option element
            if (!optionElement) return;

            const labelElement = optionElement.querySelector('label');
            if (!labelElement) return;

            const label = labelElement.textContent.trim();

            // Match by checking if the name starts with the filterConfig name (handles array names like 'genres[]')
            const filterType = Object.keys(filterConfig).find(key => {
                const configName = filterConfig[key].name;
                return name === configName || (configName.endsWith('[]') && name.startsWith(configName.replace('[]', '')));
            });

            if (filterType) {
                selectedFilters.push({
                    type: filterType,
                    filterLabel: filterConfig[filterType].label,
                    value: value,
                    label: label,
                    input: checkbox
                });
            }
        });

        // Get selected radio button (sort) within filter dropdowns only
        const selectedRadio = document.querySelector('.custom-select-dropdown input[type="radio"]:checked');
        if (selectedRadio) {
            const name = selectedRadio.name;
            const value = selectedRadio.value;
            const optionElement = selectedRadio.closest('.custom-select-option');

            if (optionElement) {
                const labelElement = optionElement.querySelector('label');
                if (labelElement) {
                    const label = labelElement.textContent.trim();
                    const filterType = Object.keys(filterConfig).find(key => filterConfig[key].name === name);

                    if (filterType) {
                        selectedFilters.push({
                            type: filterType,
                            filterLabel: filterConfig[filterType].label,
                            value: value,
                            label: label,
                            input: selectedRadio
                        });
                    }
                }
            }
        }

        // Create badges for each selected filter
        selectedFilters.forEach(filter => {
            const badge = document.createElement('div');
            badge.className = 'inline-flex items-center gap-2 px-3 py-1 bg-primary text-white rounded-full text-sm font-medium';
            badge.setAttribute('data-filter-type', filter.type);
            badge.setAttribute('data-filter-value', filter.value);

            // Get icon for this filter type
            const iconKey = filterConfig[filter.type]?.iconKey || '';
            const iconHtml = getSvgIcon(iconKey);
            // Replace fill color to match badge text (white)
            const iconHtmlWhite = iconHtml.replace('fill="#000000"', 'fill="currentColor"');

            badge.innerHTML = `
                <div class="inline-flex items-center">${iconHtmlWhite ? `<span class="mr-1">${iconHtmlWhite}</span>` : ''} <span>${filter.label}</span></div>
                <button type="button" class="remove-filter-btn ml-1 hover:bg-primary-dark text-white rounded-full p-0.5 transition-colors" aria-label="Remove filter">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            `;

            // Add remove functionality
            const removeBtn = badge.querySelector('.remove-filter-btn');
            removeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                // Uncheck the corresponding input
                filter.input.checked = false;
                // Trigger change event to update dropdown text
                filter.input.dispatchEvent(new Event('change', {bubbles: true}));
                // Update badges
                updateSelectedFilters();
            });

            selectedFiltersDiv.appendChild(badge);
        });

        // Show/hide container based on whether there are any filters
        if (selectedFiltersContainer) {
            if (selectedFilters.length > 0) {
                selectedFiltersContainer.classList.remove('hidden');
            } else {
                selectedFiltersContainer.classList.add('hidden');
            }
        }
    }

// Suggested Filter Badge Click Handler
    document.querySelectorAll('.suggested-filter-badge').forEach(badge => {
        badge.addEventListener('click', function () {
            const termId = this.getAttribute('data-term-id');
            const taxonomy = this.getAttribute('data-taxonomy');
            const isSelected = this.getAttribute('data-selected') === 'true';

            // Find the corresponding checkbox in the dropdown
            const checkbox = document.querySelector(`input[type="checkbox"][name="${taxonomy}[]"][value="${termId}"]`);

            if (checkbox) {
                // Toggle checkbox
                checkbox.checked = !isSelected;

                // Trigger change event to update dropdown text
                checkbox.dispatchEvent(new Event('change', {bubbles: true}));

                // Update badge style
                if (!isSelected) {
                    this.classList.remove('bg-gray-100', 'text-gray-800', 'hover:bg-gray-200');
                    this.classList.add('bg-primary', 'text-white');
                    this.setAttribute('data-selected', 'true');
                } else {
                    this.classList.remove('bg-primary', 'text-white');
                    this.classList.add('bg-gray-100', 'text-gray-800', 'hover:bg-gray-200');
                    this.setAttribute('data-selected', 'false');
                }

                // Update selected filters badges
                setTimeout(() => {
                    updateSelectedFilters();
                }, 10);
            }
        });
    });

// Function to update suggested filter badge states when filters change
    function updateSuggestedFilterBadges() {
        document.querySelectorAll('.suggested-filter-badge').forEach(badge => {
            const termId = badge.getAttribute('data-term-id');
            const taxonomy = badge.getAttribute('data-taxonomy');
            const checkbox = document.querySelector(`input[type="checkbox"][name="${taxonomy}[]"][value="${termId}"]`);

            if (checkbox) {
                const isSelected = checkbox.checked;
                badge.setAttribute('data-selected', isSelected ? 'true' : 'false');

                if (isSelected) {
                    badge.classList.remove('bg-gray-100', 'text-gray-800', 'hover:bg-gray-200');
                    badge.classList.add('bg-primary', 'text-white');
                } else {
                    badge.classList.remove('bg-primary', 'text-white');
                    badge.classList.add('bg-gray-100', 'text-gray-800', 'hover:bg-gray-200');
                }
            }
        });
    }

// Hook into all checkbox and radio changes to update badges using event delegation
// This ensures we catch all changes even if elements are added dynamically
    document.addEventListener('change', (e) => {
        // Check if the changed element is a checkbox or radio within a filter dropdown
        if ((e.target.type === 'checkbox' || e.target.type === 'radio') &&
            e.target.closest('.custom-select-dropdown')) {
            // Small delay to let existing handlers update the dropdown text first
            setTimeout(() => {
                updateSelectedFilters();
                updateSuggestedFilterBadges();
            }, 10);
        }
    });

// Initial update of selected filters (run after DOM is ready)
    function initSelectedFilters() {
        updateSelectedFilters();
        updateSuggestedFilterBadges();

        // Update selected text for all dropdowns based on checked inputs
        document.querySelectorAll('.custom-select-wrapper').forEach(wrapper => {
            const selectedText = wrapper.querySelector('.selected-text');
            const dropdown = wrapper.querySelector('.custom-select-dropdown');
            if (!selectedText || !dropdown) return;

            const checkedInputs = dropdown.querySelectorAll('input:checked');

            if (checkedInputs.length === 0) {
                const placeholder = selectedText.id.replace('-selected-text', '');
                let placeholderText = 'Select ';
                if (placeholder.includes('genre')) placeholderText = 'Select Genre';
                else if (placeholder.includes('collection')) placeholderText = 'Select Collection';
                else if (placeholder.includes('type')) placeholderText = 'Select App Type';
                else if (placeholder.includes('sort')) placeholderText = 'Select Sort';
                selectedText.textContent = placeholderText;
                selectedText.classList.remove('has-selection');
            } else if (checkedInputs.length === 1) {
                const optionElement = checkedInputs[0].closest('.custom-select-option');
                if (optionElement) {
                    const labelElement = optionElement.querySelector('label');
                    if (labelElement) {
                        selectedText.textContent = labelElement.textContent.trim();
                        selectedText.classList.add('has-selection');
                    }
                }
            } else {
                selectedText.textContent = `${checkedInputs.length} selected`;
                selectedText.classList.add('has-selection');
            }
        });
    }

// Run initialization when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            setTimeout(initSelectedFilters, 100);
        });
    } else {
        // DOM is already ready
        setTimeout(initSelectedFilters, 100);
    }

    const searchInput = document.getElementById('searchInput');
    const clearFiltersBtn = document.getElementById('clearFilters');

    document.addEventListener('DOMContentLoaded', () => {
        const btn = document.getElementById('clearFilters');
        if (btn) {
            btn.addEventListener('click', (e) => {
                e.preventDefault();

                const input = document.getElementById('searchInput');
                if (input) {
                    input.value = '';
                }

                // Uncheck all checkboxes (genre, collection, type)
                document.querySelectorAll('input[type="checkbox"]:checked').forEach(checkbox => {
                    checkbox.checked = false;
                    checkbox.dispatchEvent(new Event('change', {bubbles: true}));
                });

                // Uncheck selected radio button (sort)
                const selectedRadio = document.querySelector('input[type="radio"]:checked');
                if (selectedRadio) {
                    selectedRadio.checked = false;
                    selectedRadio.dispatchEvent(new Event('change', {bubbles: true}));
                }

                updateSelectedFilters();
                updateSuggestedFilterBadges();
            });
        }
    });
})();