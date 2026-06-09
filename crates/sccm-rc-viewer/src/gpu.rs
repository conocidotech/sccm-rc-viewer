//! Optional GPU renderer (wgpu). Uploads the remote desktop framebuffer as a
//! texture and draws it as a bilinear-sampled quad below the toolbar strip —
//! moving the per-frame scaling off the CPU. A second quad draws the toolbar (or
//! the connect/closed splash) as an overlay texture: the toolbar is still
//! rasterised by `toolbar.rs`/`text.rs` into a small CPU buffer, then uploaded.
//!
//! The softbuffer path stays as the default/fallback (see `main.rs`); the GPU
//! path is enabled with `SCCM_RC_GPU=1`. Follow-ups: a client-cursor quad (the
//! clean #87 fix) and dirty-region uploads.

use std::sync::Arc;
use winit::window::Window;

/// Toolbar strip background (matches `toolbar::BAR_BG`), linear-ish for the clear.
const BAR_CLEAR: wgpu::Color = wgpu::Color { r: 0.027, g: 0.027, b: 0.028, a: 1.0 };

/// NDC destination rectangle for a quad (min = bottom-left, max = top-right).
#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct RectUniform {
    min: [f32; 2],
    max: [f32; 2],
}

/// A texture + its bind group + the pixel size it was created for.
struct Layer {
    texture: wgpu::Texture,
    bind: wgpu::BindGroup,
    w: u32,
    h: u32,
}

/// Where an overlay quad is drawn. `TopStrip(h)` covers the top `h` pixels (the
/// toolbar); `Full` covers the whole window (the connect/closed splash).
pub enum OverlayDest {
    TopStrip(u32),
    Full,
}

pub struct GpuRenderer {
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,
    pipeline: wgpu::RenderPipeline,
    sampler: wgpu::Sampler,
    bind_layout: wgpu::BindGroupLayout,
    uniform_desktop: wgpu::Buffer,
    uniform_overlay: wgpu::Buffer,
    desktop: Option<Layer>,
    overlay: Option<Layer>,
}

impl GpuRenderer {
    pub fn new(window: Arc<Window>, width: u32, height: u32) -> Result<Self, String> {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::default());
        let surface = instance
            .create_surface(window)
            .map_err(|e| format!("create_surface: {e}"))?;

        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::LowPower,
            compatible_surface: Some(&surface),
            force_fallback_adapter: false,
        }))
        .ok_or_else(|| "no compatible GPU adapter".to_string())?;

        let (device, queue) = pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: Some("sccm-rc device"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::downlevel_defaults(),
                memory_hints: wgpu::MemoryHints::Performance,
            },
            None,
        ))
        .map_err(|e| format!("request_device: {e}"))?;

        let caps = surface.get_capabilities(&adapter);
        let format = caps
            .formats
            .iter()
            .copied()
            .find(|f| f.is_srgb())
            .unwrap_or(caps.formats[0]);
        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            width: width.max(1),
            height: height.max(1),
            present_mode: wgpu::PresentMode::Fifo,
            alpha_mode: caps.alpha_modes[0],
            view_formats: vec![],
            desired_maximum_frame_latency: 2,
        };
        surface.configure(&device, &config);

        let bind_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("quad bind layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Texture {
                        sample_type: wgpu::TextureSampleType::Float { filterable: true },
                        view_dimension: wgpu::TextureViewDimension::D2,
                        multisampled: false,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::VERTEX,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("quad shader"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("quad pipeline layout"),
            bind_group_layouts: &[&bind_layout],
            push_constant_ranges: &[],
        });
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("quad pipeline"),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: "vs",
                buffers: &[],
                compilation_options: Default::default(),
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: "fs",
                targets: &[Some(wgpu::ColorTargetState {
                    format,
                    blend: Some(wgpu::BlendState::ALPHA_BLENDING),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
                compilation_options: Default::default(),
            }),
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview: None,
            cache: None,
        });

        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("quad sampler"),
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });
        let uniform_desc = wgpu::BufferDescriptor {
            label: Some("rect uniform"),
            size: std::mem::size_of::<RectUniform>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        };
        let uniform_desktop = device.create_buffer(&uniform_desc);
        let uniform_overlay = device.create_buffer(&uniform_desc);

        Ok(Self {
            surface,
            device,
            queue,
            config,
            pipeline,
            sampler,
            bind_layout,
            uniform_desktop,
            uniform_overlay,
            desktop: None,
            overlay: None,
        })
    }

    fn resize(&mut self, width: u32, height: u32) {
        self.config.width = width.max(1);
        self.config.height = height.max(1);
        self.surface.configure(&self.device, &self.config);
    }

    /// (Re)create a layer's texture + bind group when its pixel size changes.
    fn ensure_layer(
        device: &wgpu::Device,
        bind_layout: &wgpu::BindGroupLayout,
        sampler: &wgpu::Sampler,
        uniform: &wgpu::Buffer,
        slot: &mut Option<Layer>,
        w: u32,
        h: u32,
    ) {
        if let Some(l) = slot {
            if l.w == w && l.h == h {
                return;
            }
        }
        let texture = device.create_texture(&wgpu::TextureDescriptor {
            label: Some("quad texture"),
            size: wgpu::Extent3d { width: w, height: h, depth_or_array_layers: 1 },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::Rgba8UnormSrgb,
            usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
            view_formats: &[],
        });
        let view = texture.create_view(&wgpu::TextureViewDescriptor::default());
        let bind = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("quad bind group"),
            layout: bind_layout,
            entries: &[
                wgpu::BindGroupEntry { binding: 0, resource: wgpu::BindingResource::TextureView(&view) },
                wgpu::BindGroupEntry { binding: 1, resource: wgpu::BindingResource::Sampler(sampler) },
                wgpu::BindGroupEntry { binding: 2, resource: uniform.as_entire_binding() },
            ],
        });
        *slot = Some(Layer { texture, bind, w, h });
    }

    fn write_layer(queue: &wgpu::Queue, layer: &Layer, rgba: &[u8]) {
        queue.write_texture(
            wgpu::ImageCopyTexture {
                texture: &layer.texture,
                mip_level: 0,
                origin: wgpu::Origin3d::ZERO,
                aspect: wgpu::TextureAspect::All,
            },
            rgba,
            wgpu::ImageDataLayout {
                offset: 0,
                bytes_per_row: Some(4 * layer.w),
                rows_per_image: Some(layer.h),
            },
            wgpu::Extent3d { width: layer.w, height: layer.h, depth_or_array_layers: 1 },
        );
    }

    /// Render one frame: an optional desktop quad (drawn below `bar_h`) and an
    /// optional overlay quad (toolbar strip or full-window splash).
    pub fn render(
        &mut self,
        win_w: u32,
        win_h: u32,
        bar_h: u32,
        desktop: Option<(u32, u32, &[u8])>,
        overlay: Option<(u32, u32, &[u8], OverlayDest)>,
    ) {
        if win_w != self.config.width || win_h != self.config.height {
            self.resize(win_w, win_h);
        }
        let top_ndc = |px: u32| 1.0 - 2.0 * (px as f32) / (win_h as f32);

        // Desktop: fills y in [bar_h, win_h].
        let mut draw_desktop = false;
        if let Some((fb_w, fb_h, rgba)) = desktop {
            if fb_w > 0 && fb_h > 0 && rgba.len() >= (fb_w * fb_h * 4) as usize {
                Self::ensure_layer(&self.device, &self.bind_layout, &self.sampler, &self.uniform_desktop, &mut self.desktop, fb_w, fb_h);
                if let Some(l) = &self.desktop {
                    Self::write_layer(&self.queue, l, rgba);
                }
                let rect = RectUniform { min: [-1.0, -1.0], max: [1.0, top_ndc(bar_h)] };
                self.queue.write_buffer(&self.uniform_desktop, 0, bytemuck::bytes_of(&rect));
                draw_desktop = true;
            }
        }

        // Overlay: toolbar strip or full-window splash.
        let mut draw_overlay = false;
        if let Some((ov_w, ov_h, rgba, dest)) = overlay {
            if ov_w > 0 && ov_h > 0 && rgba.len() >= (ov_w * ov_h * 4) as usize {
                Self::ensure_layer(&self.device, &self.bind_layout, &self.sampler, &self.uniform_overlay, &mut self.overlay, ov_w, ov_h);
                if let Some(l) = &self.overlay {
                    Self::write_layer(&self.queue, l, rgba);
                }
                let rect = match dest {
                    OverlayDest::Full => RectUniform { min: [-1.0, -1.0], max: [1.0, 1.0] },
                    OverlayDest::TopStrip(h) => RectUniform { min: [-1.0, top_ndc(h)], max: [1.0, 1.0] },
                };
                self.queue.write_buffer(&self.uniform_overlay, 0, bytemuck::bytes_of(&rect));
                draw_overlay = true;
            }
        }

        let surface_tex = match self.surface.get_current_texture() {
            Ok(t) => t,
            Err(wgpu::SurfaceError::Lost | wgpu::SurfaceError::Outdated) => {
                self.surface.configure(&self.device, &self.config);
                return;
            }
            Err(_) => return,
        };
        let view = surface_tex.texture.create_view(&wgpu::TextureViewDescriptor::default());
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("frame") });
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("frame pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(BAR_CLEAR),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
            });
            pass.set_pipeline(&self.pipeline);
            if draw_desktop {
                if let Some(l) = &self.desktop {
                    pass.set_bind_group(0, &l.bind, &[]);
                    pass.draw(0..6, 0..1);
                }
            }
            if draw_overlay {
                if let Some(l) = &self.overlay {
                    pass.set_bind_group(0, &l.bind, &[]);
                    pass.draw(0..6, 0..1);
                }
            }
        }
        self.queue.submit(Some(encoder.finish()));
        surface_tex.present();
    }

    /// Debug: render the current layers into an offscreen texture and save it as
    /// a PNG (GDI can't screenshot a Vulkan swapchain). Used for self-verification
    /// via SCCM_RC_GPU_DUMP=<path>. Reuses the bind groups from the last render().
    pub fn dump_png(&self, path: &str) -> Result<(), String> {
        let (w, h) = (self.config.width, self.config.height);
        // The offscreen target MUST use the surface format the pipeline was built
        // for (e.g. Bgra8UnormSrgb), or wgpu rejects the render pass as incompatible.
        let tex = self.device.create_texture(&wgpu::TextureDescriptor {
            label: Some("dump target"),
            size: wgpu::Extent3d { width: w, height: h, depth_or_array_layers: 1 },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: self.config.format,
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
            view_formats: &[],
        });
        let view = tex.create_view(&wgpu::TextureViewDescriptor::default());
        let align = wgpu::COPY_BYTES_PER_ROW_ALIGNMENT;
        let bpr = (4 * w).div_ceil(align) * align;
        let buf = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("dump readback"),
            size: (bpr * h) as u64,
            usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            mapped_at_creation: false,
        });
        let mut enc = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor { label: Some("dump") });
        {
            let mut pass = enc.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("dump pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    ops: wgpu::Operations { load: wgpu::LoadOp::Clear(BAR_CLEAR), store: wgpu::StoreOp::Store },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
            });
            pass.set_pipeline(&self.pipeline);
            if let Some(l) = &self.desktop {
                pass.set_bind_group(0, &l.bind, &[]);
                pass.draw(0..6, 0..1);
            }
            if let Some(l) = &self.overlay {
                pass.set_bind_group(0, &l.bind, &[]);
                pass.draw(0..6, 0..1);
            }
        }
        enc.copy_texture_to_buffer(
            wgpu::ImageCopyTexture { texture: &tex, mip_level: 0, origin: wgpu::Origin3d::ZERO, aspect: wgpu::TextureAspect::All },
            wgpu::ImageCopyBuffer {
                buffer: &buf,
                layout: wgpu::ImageDataLayout { offset: 0, bytes_per_row: Some(bpr), rows_per_image: Some(h) },
            },
            wgpu::Extent3d { width: w, height: h, depth_or_array_layers: 1 },
        );
        self.queue.submit(Some(enc.finish()));

        let slice = buf.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| {
            let _ = tx.send(r);
        });
        self.device.poll(wgpu::Maintain::Wait);
        rx.recv().map_err(|e| e.to_string())?.map_err(|e| format!("map: {e:?}"))?;
        let data = slice.get_mapped_range();
        let mut img = vec![0u8; (4 * w * h) as usize];
        let row = (4 * w) as usize;
        for y in 0..h as usize {
            let src = y * bpr as usize;
            let dst = y * row;
            img[dst..dst + row].copy_from_slice(&data[src..src + row]);
        }
        drop(data);
        buf.unmap();
        // The surface is typically BGRA; PNG wants RGBA, so swap R/B.
        if matches!(
            self.config.format,
            wgpu::TextureFormat::Bgra8UnormSrgb | wgpu::TextureFormat::Bgra8Unorm
        ) {
            for px in img.chunks_exact_mut(4) {
                px.swap(0, 2);
            }
        }
        image::RgbaImage::from_raw(w, h, img)
            .ok_or_else(|| "from_raw".to_string())?
            .save(path)
            .map_err(|e| e.to_string())
    }

    /// Install a non-panicking device error handler so a wgpu validation error
    /// logs instead of aborting the process (and poisoning the shared frame lock).
    pub fn set_error_handler(&self) {
        self.device.on_uncaptured_error(Box::new(|e| {
            tracing::error!(error = %e, "wgpu uncaptured error");
        }));
    }
}

/// Fullscreen-quad shader: 6 vertices positioned into the NDC `rect` uniform,
/// sampling the texture. uv.y is flipped because the textures are top-down while
/// NDC y points up.
const SHADER: &str = r#"
struct Rect { min: vec2<f32>, max: vec2<f32> };
@group(0) @binding(0) var tex: texture_2d<f32>;
@group(0) @binding(1) var samp: sampler;
@group(0) @binding(2) var<uniform> rect: Rect;

struct VsOut {
    @builtin(position) pos: vec4<f32>,
    @location(0) uv: vec2<f32>,
};

@vertex
fn vs(@builtin(vertex_index) vi: u32) -> VsOut {
    var uvs = array<vec2<f32>, 6>(
        vec2<f32>(0.0, 0.0), vec2<f32>(1.0, 0.0), vec2<f32>(0.0, 1.0),
        vec2<f32>(0.0, 1.0), vec2<f32>(1.0, 0.0), vec2<f32>(1.0, 1.0)
    );
    let uv = uvs[vi];
    let x = mix(rect.min.x, rect.max.x, uv.x);
    let y = mix(rect.max.y, rect.min.y, uv.y); // flip: uv.y=0 -> top (max.y)
    var out: VsOut;
    out.pos = vec4<f32>(x, y, 0.0, 1.0);
    out.uv = uv;
    return out;
}

@fragment
fn fs(in: VsOut) -> @location(0) vec4<f32> {
    return textureSample(tex, samp, in.uv);
}
"#;
